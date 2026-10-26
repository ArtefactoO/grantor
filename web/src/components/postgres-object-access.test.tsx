import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account, Binding, Connection, Permission, Resource } from '../lib/types'
import { PostgresObjectAccess } from './postgres-object-access'

const auth = vi.hoisted(() => ({ role: 'operator' }))
vi.mock('../auth/AuthProvider', async importOriginal => ({
  ...await importOriginal<typeof import('../auth/AuthProvider')>(), useAuth: () => ({ role: auth.role }),
}))

const account: Account = { id: 'alice', principal_id: null, connection_id: 'pg', kind: 'login', engine_identity: 'alice',
  authentication_scope: '', credential_mode: null, vault_path: '', status: 'active', ownership: 'unmanaged',
  attributes: { role_oid: 20 }, created_at: '', updated_at: '', bindings_projection: 'roles' }
const connection: Connection = { id: 'pg', display_name: 'app', engine: 'postgres', environment: 'test', tags: [], endpoints: [],
  execution_mode: 'connector', tls_config: {}, admin_credential_mode: 'provided', vault_admin_path: '',
  capabilities: ['postgres.object_acl.v1'], discovery_config: {}, status: 'active', server_version: '16',
  topology: { postgres_object_acl_version: 1 }, last_discovery_at: null, created_at: '', updated_at: '' }

function permission(object: string, action = 'SELECT', category = 'privilege'): Permission {
  return { id: `${object}-${action}`, connection_id: 'pg', engine: 'postgres', external_id: `opaque-${object}-${action}`, name: `${action} ON ${object}`,
    scope_resource_id: category === 'role' ? null : object, assignable: true, dangerous: false, status: 'observed',
    attributes: category === 'role' ? {} : { kind: 'postgres_object_privilege', object_kind: 'table' },
    normalized: { category, action, resource: object, scope: 'app', raw: `${action} ON ${object}`, details: null, dangerous: false, danger_reason: '' },
    created_at: '', updated_at: '' }
}
function binding(p: Permission): Binding {
  return { id: `binding-${p.id}`, account_id: account.id, permission_definition_id: p.id, scope_resource_id: p.scope_resource_id,
    source: 'external', desired_state: null, observed_state: 'present', observed_effective: true, status: 'observed', expires_at: null,
    observed_attributes: { grantors: [{ oid: 13, name: 'owner', grant_option: false }] }, created_at: '', updated_at: '' }
}
interface ServerGroup {
  key: string; scope_id: string; resource: string; kind: string; owner: string; public_privileges: string[]
  permissions: Permission[]; bindings: Binding[]
}
function group(object: string, granted = ['SELECT']): ServerGroup {
  const permissions = ['SELECT', 'INSERT', 'UPDATE'].map(action => permission(object, action))
  return { key: `group:${object}`, scope_id: object, resource: object, kind: 'table', owner: 'owner', public_privileges: [],
    permissions, bindings: permissions.filter(p => granted.includes(p.normalized.action)).map(binding) }
}
function catalog(size: number): ServerGroup[] {
  return Array.from({ length: size }, (_, i) => group(`app.public.table_${String(i).padStart(3, '0')}`))
}
interface RequestRecord { url: URL; method: string; body: unknown }
interface ServerOptions {
  objects?: ServerGroup[]; targets?: ServerGroup[]; defaults?: Record<string, unknown>[]
  available?: boolean; inventoryStatus?: string; mutationStatus?: number; failObjectCursor?: boolean
}
function mockServer(options: ServerOptions = {}) {
  const requests: RequestRecord[] = [], objects = options.objects ?? [], targets = options.targets ?? objects, defaults = options.defaults ?? []
  const cursors = new Map<string, { kind: string; query: string; offset: number }>()
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  const page = <T,>(items: T[], url: URL, kind: string) => {
    const query = url.searchParams.get('q') ?? '', cursor = url.searchParams.get('cursor')
    const decoded = cursor === null ? undefined : cursors.get(cursor)
    if (cursor !== null && (decoded === undefined || decoded.kind !== kind || decoded.query !== query)) throw new Error('invalid opaque cursor')
    const offset = decoded?.offset ?? 0, limit = Number(url.searchParams.get('limit') ?? 8)
    const next = offset + limit < items.length ? `opaque/${kind} ${query}:${offset + limit}?signed=token&v=1+` : ''
    if (next !== '') cursors.set(next, { kind, query, offset: offset + limit })
    return { items: items.slice(offset, offset + limit), next_cursor: next, total_entries: items.length }
  }
  const inventory = { status: options.inventoryStatus ?? 'current', refresh_required: options.inventoryStatus === 'partial',
    observed_at: '2026-10-20T10:00:00Z', snapshot_version: 'snapshot-1', role_policy_versions: {} }
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input), 'https://grantor.test'), method = init?.method ?? 'GET'
    requests.push({ url, method, body: init?.body === undefined ? null : JSON.parse(String(init.body)) })
    if (method === 'POST' && url.pathname === '/api/v1/accounts/alice/object-privileges') {
      return options.mutationStatus === 409 ? json({ error: 'column ACL requires separate review' }, 409) : json({ operation_id: 'change-1', children: [] }, 202)
    }
    if (method === 'GET' && url.pathname === '/api/v1/accounts/alice/object-privileges') {
      const scope = url.searchParams.get('scope_resource_id')
      if (scope !== null) return json({ objects: targets.filter(item => item.scope_id === scope), available: options.available ?? true, total_entries: 1, next_cursor: '', snapshot_version: 'snapshot-1', inventory })
      if (options.failObjectCursor && url.searchParams.has('cursor')) return json({ error: 'inventory_snapshot_changed: reload the first page' }, 409)
      const query = (url.searchParams.get('q') ?? '').toLowerCase(), result = page(objects.filter(item => item.resource.toLowerCase().includes(query)), url, 'objects')
      return json({ objects: result.items, total_entries: result.total_entries, next_cursor: result.next_cursor,
        snapshot_version: 'snapshot-1', available: options.available ?? true, inventory })
    }
    if (method === 'GET' && url.pathname === '/api/v1/connections/pg/object-privilege-targets') {
      const query = (url.searchParams.get('q') ?? '').toLowerCase(), result = page(targets.filter(item => item.resource.toLowerCase().includes(query)), url, 'targets')
      return json({ objects: result.items.map(({ scope_id, resource, kind, owner }) => ({ scope_id, resource, kind, owner })), next_cursor: result.next_cursor, snapshot_version: 'snapshot-1' })
    }
    if (method === 'GET' && url.pathname === '/api/v1/accounts/alice/default-privileges') {
      const query = (url.searchParams.get('q') ?? '').toLowerCase(), result = page(defaults.filter(item => JSON.stringify(item).toLowerCase().includes(query)), url, 'defaults')
      return json({ rules: result.items, total_entries: result.total_entries, next_cursor: result.next_cursor,
        snapshot_version: 'snapshot-1', available: options.available ?? true, inventory })
    }
    throw new Error(`unexpected ${method} ${url.pathname}${url.search}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { requests, options, fetchMock, objects, targets,
    gets: (route: string) => requests.filter(request => request.method === 'GET' && request.url.pathname.endsWith(route)),
    mutations: () => requests.filter(request => request.method === 'POST') }
}

const clients: QueryClient[] = []
function mount(count: number, overrides: { connection?: Partial<Connection>; roleBindings?: Binding[]; account?: Partial<Account> } = {}) {
  const started = vi.fn(), role = permission('r_app', '', 'role')
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  clients.push(client)
  render(<QueryClientProvider client={client}><PostgresObjectAccess account={{ ...account,
    access_summary: { direct_objects: count, direct_bindings: count, unmanaged_direct_bindings: count, unmanaged_dangerous_direct_bindings: 0, readonly_direct_bindings: 0 }, ...overrides.account }}
    connection={{ ...connection, ...overrides.connection }} permissions={[role]} bindings={overrides.roleBindings ?? [binding(role)]}
    resourcesById={new Map<string, Resource>()} onStarted={started} /></QueryClientProvider>)
  return started
}
function directSummary() { return screen.getByText('Прямые права').closest('summary')! }
afterEach(() => {
  auth.role = 'operator'
  clients.forEach(client => client.clear()); clients.length = 0
  vi.unstubAllGlobals(); vi.useRealTimers()
})

describe('PostgreSQL lazy object ACL', () => {
  it('uses the account summary while closed and requests eight objects per opaque server page', async () => {
    vi.useRealTimers()
    const user = userEvent.setup(), server = mockServer({ objects: catalog(200) })
    mount(200)
    expect(directSummary().closest('details')).not.toHaveAttribute('open')
    expect(directSummary()).toHaveTextContent('200 объектов')
    expect(server.requests).toHaveLength(0)
    expect(screen.queryByRole('button', { name: 'Изменить' })).not.toBeInTheDocument()
    await user.click(directSummary())
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Изменить' })).toHaveLength(8))
    expect(server.gets('/object-privileges')).toHaveLength(1)
    const first = server.gets('/object-privileges')[0].url
    expect(first.searchParams.get('limit')).toBe('8')
    expect(first.searchParams.get('q')).toBe('')
    expect(first.searchParams.has('cursor')).toBe(false)
    expect(server.gets('/object-privilege-targets')).toHaveLength(0)
    expect(server.gets('/default-privileges')).toHaveLength(0)
    expect(screen.queryByText('app.public.table_199')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Показать ещё' }))
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Изменить' })).toHaveLength(16))
    const second = server.gets('/object-privileges')[1].url
    expect(second.searchParams.get('limit')).toBe('8')
    expect(second.searchParams.get('cursor')).toBe('opaque/objects :8?signed=token&v=1+')
    expect(screen.getByText('Показано 16 из 200')).toBeInTheDocument()
    expect(server.gets('/object-privileges')).toHaveLength(2)
  })

  it('debounces server search and starts a new first page instead of filtering loaded pages', async () => {
    vi.useRealTimers()
    const user = userEvent.setup(), server = mockServer({ objects: catalog(200) })
    mount(200)
    await user.click(directSummary())
    await screen.findByText('app.public.table_000')
    await user.click(screen.getByRole('button', { name: 'Показать ещё' }))
    await screen.findByText('app.public.table_015')
    await user.type(screen.getByRole('textbox', { name: 'Поиск прямых прав' }), '199')
    await screen.findByText('app.public.table_199')
    const searched = server.gets('/object-privileges').filter(request => request.url.searchParams.get('q') !== '')
    expect(searched).toHaveLength(1)
    expect(searched[0].url.searchParams.get('q')).toBe('199')
    expect(searched[0].url.searchParams.get('limit')).toBe('8')
    expect(searched[0].url.searchParams.has('cursor')).toBe(false)
    expect(screen.queryByText('app.public.table_000')).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Изменить' })).toHaveLength(1)
    expect(screen.getByText('Показано 1 из 1')).toBeInTheDocument()
  })

  it('submits one object delta without resending roles or other objects', async () => {
    const user = userEvent.setup(), selected = group('app.public.items'), other = group('app.public.other')
    const server = mockServer({ objects: [selected, other] }), before = structuredClone(server.objects), started = mount(2)
    await user.click(directSummary())
    await screen.findByText(selected.resource)
    await user.click(within(screen.getByText(selected.resource).closest('li')!).getByRole('button', { name: 'Изменить' }))
    const drawer = screen.getByRole('dialog', { name: 'Изменить прямые права' })
    await user.click(within(drawer).getByRole('checkbox', { name: 'SELECT' }))
    await user.click(within(drawer).getByRole('checkbox', { name: 'INSERT' }))
    await user.click(within(drawer).getByRole('button', { name: 'Проверить изменения' }))
    expect(screen.getByText(/У учетки также есть назначения ролей/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    await waitFor(() => expect(started).toHaveBeenCalledWith('change-1', 'Изменение прямых прав alice'))
    expect(server.mutations()).toHaveLength(1)
    expect(server.mutations()[0].url.pathname).toBe('/api/v1/accounts/alice/object-privileges')
    expect(server.mutations()[0].body).toEqual({ add_permission_ids: ['app.public.items-INSERT'], remove_binding_ids: ['binding-app.public.items-SELECT'], confirm: false })
    expect(server.objects).toEqual(before)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('keeps the review drawer and original grants after a mutation conflict', async () => {
    const user = userEvent.setup(), selected = group('app.public.items'), server = mockServer({ objects: [selected], mutationStatus: 409 }), started = mount(1)
    await user.click(directSummary())
    await user.click(await screen.findByRole('button', { name: 'Изменить' }))
    await user.click(screen.getByRole('checkbox', { name: 'SELECT' }))
    await user.click(screen.getByRole('button', { name: 'Проверить изменения' }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    expect(await screen.findByText('column ACL requires separate review')).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Проверить изменения' })).toBeInTheDocument()
    expect(started).not.toHaveBeenCalled()
    expect(server.mutations()).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: 'Назад' }))
    expect(screen.getByRole('checkbox', { name: 'SELECT' })).not.toBeChecked()
    expect(selected.bindings[0].observed_state).toBe('present')
  })

  it('marks a cursor conflict stale and reloads only the first page on explicit refresh', async () => {
    const user = userEvent.setup(), server = mockServer({ objects: catalog(200), failObjectCursor: true })
    mount(200)
    await user.click(directSummary())
    await screen.findByText('app.public.table_000')
    await user.click(screen.getByRole('button', { name: 'Показать ещё' }))
    expect(await screen.findByText('Инвентарь обновился. Загрузите список заново.')).toBeInTheDocument()
    expect(server.gets('/object-privileges')).toHaveLength(2)
    server.options.failObjectCursor = false
    await user.click(screen.getByRole('button', { name: 'Обновить список' }))
    await waitFor(() => expect(screen.queryByText('Инвентарь обновился. Загрузите список заново.')).not.toBeInTheDocument())
    expect(server.gets('/object-privileges')).toHaveLength(3)
    expect(server.gets('/object-privileges')[2].url.searchParams.has('cursor')).toBe(false)
    expect(screen.getAllByRole('button', { name: 'Изменить' })).toHaveLength(8)
    expect(screen.getByText('Показано 8 из 200')).toBeInTheDocument()
  })

  it.each(['viewer', 'policy'])('keeps %s grants read-only', async mode => {
    if (mode === 'viewer') auth.role = 'viewer'
    mockServer({ objects: [group('app.public.items')] })
    mount(1, mode === 'policy' ? { connection: { discovery_config: { postgres_role_policy_templates: [{ role_name: 'alice' }] } } } : {})
    await userEvent.click(directSummary())
    await screen.findByText('app.public.items')
    expect(screen.queryByRole('button', { name: 'Изменить' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать прямой доступ' })).not.toBeInTheDocument()
  })

  it('does not present an incomplete snapshot as proof of no direct rights', async () => {
    const server = mockServer({ objects: [], inventoryStatus: 'partial' })
    mount(0, { connection: { topology: { postgres_object_acl_version: 1, postgres_object_acl_incomplete_scopes: ['db:unavailable'] } } })
    expect(screen.getByText('Недостаточно данных')).toBeInTheDocument()
    expect(server.requests).toHaveLength(0)
    await userEvent.click(directSummary())
    await waitFor(() => expect(server.gets('/object-privileges')).toHaveLength(1))
    expect(screen.getByText(/Часть баз недоступна/)).toBeInTheDocument()
    expect(screen.queryByText('Прямых grants не обнаружено')).not.toBeInTheDocument()
  })

  it('searches twenty targets and loads one selected scope for a new grant without bindings', async () => {
    vi.useRealTimers()
    const user = userEvent.setup(), targets = catalog(400).map(item => ({ ...item, bindings: [] })), server = mockServer({ objects: [], targets })
    const started = mount(0, { roleBindings: [] })
    expect(server.requests).toHaveLength(0)
    await user.click(directSummary())
    await user.click(await screen.findByRole('button', { name: 'Выдать прямой доступ' }))
    const drawer = screen.getByRole('dialog', { name: 'Изменить прямые права' })
    await within(drawer).findByRole('option', { name: 'app.public.table_000' })
    expect(server.gets('/object-privilege-targets')[0].url.searchParams.get('limit')).toBe('20')
    expect(within(drawer).getAllByRole('option')).toHaveLength(21)
    expect(within(drawer).getByText('Показаны первые 20 совпадений. Уточните поиск.')).toBeInTheDocument()
    expect(within(drawer).queryByRole('option', { name: 'app.public.table_397' })).not.toBeInTheDocument()
    await user.type(within(drawer).getByRole('textbox', { name: 'Поиск объекта для прямого доступа' }), '397')
    await within(drawer).findByRole('option', { name: 'app.public.table_397' })
    expect(server.gets('/object-privilege-targets')).toHaveLength(2)
    expect(server.gets('/object-privilege-targets')[1].url.searchParams.get('q')).toBe('397')
    expect(server.gets('/object-privilege-targets')[1].url.searchParams.get('limit')).toBe('20')
    await user.selectOptions(within(drawer).getByRole('combobox', { name: 'Объект' }), 'app.public.table_397')
    await within(drawer).findByRole('checkbox', { name: 'SELECT' })
    const selectedRequests = server.gets('/object-privileges').filter(request => request.url.searchParams.has('scope_resource_id'))
    expect(selectedRequests).toHaveLength(1)
    expect(selectedRequests[0].url.searchParams.get('scope_resource_id')).toBe('app.public.table_397')
    expect(selectedRequests[0].url.searchParams.has('cursor')).toBe(false)
    await user.click(within(drawer).getByRole('checkbox', { name: 'SELECT' }))
    await user.click(within(drawer).getByRole('button', { name: 'Проверить изменения' }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    await waitFor(() => expect(started).toHaveBeenCalledOnce())
    expect(server.mutations()[0].body).toEqual({ add_permission_ids: ['app.public.table_397-SELECT'], remove_binding_ids: [], confirm: false })
    expect(server.gets('/default-privileges')).toHaveLength(0)
  })

  it('loads future default grants only inside their disclosure and pages them separately', async () => {
    const user = userEvent.setup(), defaults = Array.from({ length: 200 }, (_, i) => ({ database: 'app', creator: `owner_${String(i).padStart(3, '0')}`, schema: 'public', kind: 'r', grantee: 'reader', privilege: 'SELECT', grant_option: i === 0 }))
    const server = mockServer({ objects: catalog(200), defaults })
    mount(200)
    const summary = screen.getByText('Новые объекты').closest('summary')!, disclosure = summary.closest('details')!
    expect(disclosure).not.toHaveAttribute('open')
    expect(server.requests).toHaveLength(0)
    await user.click(summary)
    await within(disclosure).findByText(/owner_000/)
    expect(within(disclosure).getByText(/owner_000/)).toHaveTextContent('WITH GRANT OPTION')
    expect(within(disclosure).getByText(/owner_001/)).not.toHaveTextContent('WITH GRANT OPTION')
    expect(server.gets('/object-privileges')).toHaveLength(0)
    expect(server.gets('/object-privilege-targets')).toHaveLength(0)
    expect(server.gets('/default-privileges')).toHaveLength(1)
    expect(server.gets('/default-privileges')[0].url.searchParams.get('limit')).toBe('8')
    expect(within(disclosure).queryByText(/owner_008/)).not.toBeInTheDocument()
    await user.click(within(disclosure).getByRole('button', { name: 'Показать ещё' }))
    await within(disclosure).findByText(/owner_015/)
    expect(server.gets('/default-privileges')[1].url.searchParams.get('cursor')).toBe('opaque/defaults :8?signed=token&v=1+')
    expect(within(disclosure).queryByText(/owner_016/)).not.toBeInTheDocument()
    expect(server.gets('/default-privileges')).toHaveLength(2)
    expect(within(disclosure).queryByRole('button', { name: 'Изменить' })).not.toBeInTheDocument()
  })

  it('keeps failed managed grants visible when no observed access remains', async () => {
    const failed = group('app.public.failed_grant')
    failed.bindings = [{ ...failed.bindings[0], source: 'service', desired_state: 'present', observed_state: 'absent', observed_effective: false, status: 'failed' }]
    mockServer({ objects: [failed] })
    mount(0)
    await userEvent.click(directSummary())
    expect(await screen.findByText('app.public.failed_grant')).toBeInTheDocument()
    expect(screen.getByText('Есть неподтвержденные изменения прав. Проверьте операции.')).toBeInTheDocument()
    expect(screen.queryByText('Прямых grants не обнаружено')).not.toBeInTheDocument()
  })

  it('does not show unavailable object or default snapshots as empty granted access', async () => {
    mockServer({ available: false })
    mount(0)
    await userEvent.click(directSummary())
    expect(await screen.findByText('Снимок прямых прав недоступен. Синхронизируйте подключение.')).toBeInTheDocument()
    expect(screen.queryByText('Прямых grants не обнаружено')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать прямой доступ' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('Новые объекты').closest('summary')!)
    expect(await screen.findByText('Нет снимка default privileges. Синхронизируйте подключение.')).toBeInTheDocument()
    expect(screen.queryByText('Прямых default privileges не обнаружено')).not.toBeInTheDocument()
  })
})
