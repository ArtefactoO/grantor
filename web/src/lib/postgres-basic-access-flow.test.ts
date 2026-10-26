import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  basicRoleDiscoveryIssue,
  basicRoleIntent,
  createBasicPostgresRoles,
} from './postgres-basic-access-flow'
import type { BasicRolesRunOptions } from './postgres-basic-access-flow'
import type { Connection, PostgresRolePolicy, PostgresRolePolicyTemplate, Resource, ResourceTreeItem } from './types'

const CONNECTION_ID = 'connection-1'
const CONNECTION_URL = `/api/v1/connections/${CONNECTION_ID}`
const DATABASE_ID = 'database-1'
const PINNED_VERSION = '2026-08-26T10:00:00Z'
const SAVED_VERSION = '2026-08-26T10:01:00Z'
const SYSTEM_IDENTIFIER = '7429012345678901234'
const TARGET_IDENTITY = `postgres:system:${SYSTEM_IDENTIFIER}`

function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: CONNECTION_ID, display_name: 'Basic role test connection', engine: 'postgres', environment: 'test',
    endpoints: ['postgres.test:5432'], execution_mode: 'direct', tls_config: { mode: 'verify-full' },
    tags: [], status: 'active', capabilities: ['discover', 'role.policy.apply', 'role.policy.create', 'postgres.superuser_direct.v1'],
    admin_credential_mode: 'vault', vault_admin_path: `connections/${CONNECTION_ID}/admin`,
    discovery_config: { databases: ['appdb'], excluded_schemas: ['unrelated'], other: { keep: [1, 2] } },
    topology: { system_identifier: SYSTEM_IDENTIFIER }, server_version: '16', last_discovery_at: PINNED_VERSION,
    postgres_provisioning_authority: {
      status: 'confirmed', reason: 'superuser_confirmed', observed_at: PINNED_VERSION,
      expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
      config_incarnation: 'a'.repeat(64), target_identity: TARGET_IDENTITY,
    },
    created_at: PINNED_VERSION, updated_at: PINNED_VERSION, ...overrides,
  }
}

function database(overrides: Partial<Resource> = {}): Resource {
  return {
    id: DATABASE_ID, connection_id: CONNECTION_ID, parent_id: null, kind: 'database',
    external_id: 'database:appdb', name: 'appdb', canonical_path: 'appdb',
    attributes: { owner: 'app_owner' }, fingerprint: 'database-fingerprint',
    observed_at: PINNED_VERSION, status: 'observed', ownership: 'managed',
    created_at: PINNED_VERSION, updated_at: PINNED_VERSION, ...overrides,
  }
}

function schema(name = 'public'): ResourceTreeItem {
  return {
    id: `schema-${name}`, connection_id: CONNECTION_ID, parent_id: DATABASE_ID,
    kind: 'schema', name, status: 'observed', ownership: 'unmanaged',
  }
}

function policy(template: PostgresRolePolicyTemplate, index: number): PostgresRolePolicy {
  return {
    id: `policy-${index}`, template_key: template.key, name: template.name, description: template.description,
    external_id: `role:${template.role_name}`,
    desired_spec: {
      role_name: template.role_name, database: template.database, profile: template.profile,
      schemas: [...template.schemas], owner_roles: [...template.owner_roles], creator_roles: [...template.creator_roles],
    },
    managed: false, exact: false, dangerous: false, apply_supported: true, repairable: false,
    transition_active: false, blocked_reason: '', status: 'missing', version: index + 7,
    observed_fingerprint: `observed-${index}`,
    observed_summary: { missing: ['role'], extra: [], role: { exists: false } },
  }
}

interface Call {
  path: string
  method: string
  body: Record<string, unknown>
  signal: AbortSignal | null | undefined
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function fixture({ fresh = false, topology = { system_identifier: SYSTEM_IDENTIFIER } }: { fresh?: boolean; topology?: unknown } = {}) {
  const source = connection({ topology })
  const db = database()
  const tree: ResourceTreeItem[] = [db, schema()]
  const originalIntent = basicRoleIntent(source, db, tree)
  if (!fresh) source.discovery_config = structuredClone(originalIntent.config)
  const intent = basicRoleIntent(source, db, tree)
  const state = {
    current: structuredClone(source),
    database: structuredClone(db),
    tree: structuredClone(tree),
    policies: intent.selected.map(policy),
    calls: [] as Call[],
    connectionReads: 0,
    onRead: undefined as undefined | (() => Response | Promise<Response>),
    onPatch: undefined as undefined | ((call: Call) => Response | Promise<Response>),
    onCreate: undefined as undefined | ((index: number, call: Call) => Response | Promise<Response>),
  }
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const call: Call = {
      path, method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? JSON.parse(init.body) as Record<string, unknown> : {},
      signal: init?.signal,
    }
    state.calls.push(call)
    if (path === CONNECTION_URL && call.method === 'GET') {
      state.connectionReads++
      return state.onRead?.() ?? json(state.current)
    }
    if (path === CONNECTION_URL && call.method === 'PATCH') {
      if (state.onPatch !== undefined) return state.onPatch(call)
      state.current = {
        ...state.current, updated_at: SAVED_VERSION, status: 'active', discovery_config: structuredClone(call.body.discovery_config),
      }
      return json({ ...state.current, status: 'discovering', operation_id: 'discovery-operation' }, 202)
    }
    if (call.method === 'GET' && path === `/api/v1/resources/${DATABASE_ID}`) return json(state.database)
    if (call.method === 'GET' && path === `${CONNECTION_URL}/resources?view=tree`) return json({ resources: state.tree })
    if (call.method === 'GET' && path === `${CONNECTION_URL}/role-policies`) return json({ policies: state.policies })
    const index = state.policies.findIndex((item) => path === `${CONNECTION_URL}/role-policies/${encodeURIComponent(item.template_key)}/create`)
    if (call.method === 'POST' && index !== -1) {
      return state.onCreate?.(index, call) ?? json({ operation_id: `create-${state.policies[index].desired_spec.role_name}` }, 202)
    }
    throw new Error(`Unexpected test request: ${call.method} ${path}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  const onStage = vi.fn()
  const onOperation = vi.fn()
  const run = (options: Partial<BasicRolesRunOptions> = {}) => createBasicPostgresRoles(intent, {
    signal: new AbortController().signal, onStage, onOperation, pollMs: 0, timeoutMs: 1000, ...options,
  })
  return {
    source, intent, state, fetchMock, run, onStage, onOperation,
    writes: () => state.calls.filter((call) => call.method !== 'GET'),
    creates: () => state.calls.filter((call) => call.method === 'POST'),
  }
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('basic PostgreSQL role intent', () => {
  it('pins the connection, config and database independently of later input edits', () => {
    const source = connection()
    const db = database()
    const tree = [db, schema()]
    const intent = basicRoleIntent(source, db, tree)
    const before = structuredClone({ connection: intent.connection, database: intent.database, config: intent.config })
    source.endpoints.push('different.test:5432')
    source.updated_at = SAVED_VERSION
    ;(source.discovery_config as Record<string, unknown>).other = null
    db.attributes = { owner: 'changed' }
    tree.push(schema('new_scope'))

    expect({ connection: intent.connection, database: intent.database, config: intent.config }).toEqual(before)
    expect(intent.selected.map((item) => [item.role_name, item.owner_roles, item.creator_roles]))
      .toEqual([['r_appdb', ['app_owner'], ['app_owner']], ['rw_appdb', ['app_owner'], ['app_owner']]])
    expect(intent.requestIds.size).toBe(0)
    expect(intent.operations.size).toBe(0)
  })

  it.each([
    { engine: 'mongodb' }, { status: 'draft' }, { status: 'discovering' }, { status: 'degraded' }, { status: 'disabled' },
  ])('rejects an unsuitable connection before saving anything %#', (change) => {
    expect(() => basicRoleIntent(connection(change), database(), [database(), schema()])).toThrow('активного PostgreSQL')
  })

  it.each(['pending', 'pending_approval', 'running'])('rejects active credential transition %s', (status) => {
    const source = connection({ admin_credential_change: {
      operation_id: 'credential-operation', mode: 'switch', phase: 'pending', status,
      cancel_allowed: true, target_side_effect_possible: false, retryable: false, error_code: null,
      started_at: null, updated_at: PINNED_VERSION,
    } })
    expect(() => basicRoleIntent(source, database(), [database(), schema()])).toThrow('активного PostgreSQL')
  })

  it('blocks incomplete selected database discovery without blocking unrelated skipped databases', () => {
    expect(basicRoleDiscoveryIssue(connection({ topology: { skipped_databases: [{ name: 'appdb' }] } }), 'appdb'))
      .toContain('не удалось обнаружить')
    expect(basicRoleDiscoveryIssue(connection({ topology: { skipped_databases: 'invalid' } }), 'appdb'))
      .toContain('полноту инвентаря')
    expect(basicRoleDiscoveryIssue(connection({ topology: { skipped_databases: [{ name: 'unrelated' }] } }), 'appdb')).toBeNull()
    expect(() => basicRoleIntent(connection({ topology: { skipped_databases: [{ name: 'appdb' }] } }), database(), [database(), schema()]))
      .toThrow('не удалось обнаружить')
  })
})

describe('basic PostgreSQL roles creation flow', () => {
  it('saves a fresh catalog with pinned CAS and preserved config, discovers, then creates exactly the pair', async () => {
    const test = fixture({ fresh: true })
    const result = await test.run()
    const writes = test.writes()
    expect(writes.map(({ method, path }) => [method, path])).toEqual([
      ['PATCH', CONNECTION_URL],
      ['POST', `${CONNECTION_URL}/role-policies/${test.intent.selected[0].key}/create`],
      ['POST', `${CONNECTION_URL}/role-policies/${test.intent.selected[1].key}/create`],
    ])
    expect(writes[0].body).toEqual({ updated_at: PINNED_VERSION, discovery_config: test.intent.config })
    expect(writes[0].body.discovery_config).toMatchObject(test.source.discovery_config as Record<string, unknown>)
    expect(test.state.connectionReads).toBe(2)
    expect(test.onStage.mock.calls.map(([stage]) => stage)).toEqual(['checking', 'saving', 'discovering', 'creating'])
    expect(test.onOperation.mock.calls).toEqual([
      ['Синхронизация', 'discovery-operation'], ['r_appdb', 'create-r_appdb'], ['rw_appdb', 'create-rw_appdb'],
    ])
    for (let index = 0; index < 2; index++) {
      expect(writes[index + 1].body).toEqual({
        request_id: expect.any(String), version: test.state.policies[index].version,
        observed_fingerprint: test.state.policies[index].observed_fingerprint, confirm: true,
        expected_target_identity: TARGET_IDENTITY,
      })
      expect(test.intent.requestIds.get(test.intent.selected[index].key)).toBe(writes[index + 1].body.request_id)
    }
    expect(writes[1].body.request_id).not.toBe(writes[2].body.request_id)
    expect(result).toEqual({ ready: 0, operationIds: ['create-r_appdb', 'create-rw_appdb'] })
    expect(writes.some((call) => /\/(apply|repair|adopt|revoke|accounts)(?:\/|$)/.test(call.path))).toBe(false)
  })

  it('does not patch an already saved matching catalog', async () => {
    const test = fixture()
    await test.run()
    expect(test.writes()).toHaveLength(2)
    expect(test.writes().every((call) => call.method === 'POST')).toBe(true)
    expect(test.onStage.mock.calls.map(([stage]) => stage)).toEqual(['checking', 'discovering', 'creating'])
  })

  it.each([
    { id: 'another-connection' }, { engine: 'mysql' }, { environment: 'prod' }, { execution_mode: 'connector' },
    { endpoints: ['other.test:5432'] }, { tls_config: { mode: 'disable' } },
    { vault_admin_path: 'connections/other/admin' }, { admin_credential_mode: 'another' },
  ] satisfies Partial<Connection>[])('blocks changed target source before mutation %#', async (change) => {
    const test = fixture({ fresh: true })
    Object.assign(test.state.current, change)
    await expect(test.run()).rejects.toThrow('Подключение изменилось')
    expect(test.writes()).toEqual([])
  })

  it.each([
    { system_identifier: '7429012345678905678' }, {}, { system_identifier: 1234 }, { system_identifier: 'not-a-system-id' },
  ])('rejects changed or unproven cluster identity behind the same endpoint before any create %#', async (topology) => {
    const test = fixture()
    test.state.current.topology = topology

    await expect(test.run()).rejects.toThrow('Идентичность PostgreSQL-кластера')
    expect(test.creates()).toEqual([])
    expect(test.writes()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
  })

  it('rejects a cluster identity changed by the catalog discovery before either create', async () => {
    const test = fixture({ fresh: true })
    test.state.onRead = () => {
      if (test.state.connectionReads > 1) test.state.current.topology = { system_identifier: '7429012345678905678' }
      return json(test.state.current)
    }

    await expect(test.run()).rejects.toThrow('Идентичность PostgreSQL-кластера')
    expect(test.writes().map((call) => call.method)).toEqual(['PATCH'])
    expect(test.creates()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
  })

  it('tolerates a temporarily empty topology during discovery, then verifies the original cluster', async () => {
    const test = fixture({ fresh: true })
    test.state.onPatch = (call) => {
      test.state.current = {
        ...test.state.current, discovery_config: call.body.discovery_config, updated_at: SAVED_VERSION,
        status: 'discovering', topology: {},
      }
      return json({ ...test.state.current, operation_id: 'discovery-operation' }, 202)
    }
    test.state.onRead = () => {
      if (test.state.connectionReads >= 3) {
        test.state.current.status = 'active'
        test.state.current.topology = { system_identifier: SYSTEM_IDENTIFIER }
      }
      return json(test.state.current)
    }

    await expect(test.run()).resolves.toEqual({ ready: 0, operationIds: ['create-r_appdb', 'create-rw_appdb'] })
    expect(test.state.connectionReads).toBe(3)
    expect(test.creates()).toHaveLength(2)
    expect(test.creates().map((call) => call.body.expected_target_identity)).toEqual([TARGET_IDENTITY, TARGET_IDENTITY])
  })

  it.each([
    { name: 'missing', topology: {} }, { name: 'legacy numeric', topology: { system_identifier: 1234 } },
  ])('requires fresh user confirmation when discovery proves a previously $name cluster identity', async ({ topology }) => {
    const test = fixture({ fresh: true, topology })
    test.state.onRead = () => {
      if (test.state.connectionReads > 1) test.state.current.topology = { system_identifier: SYSTEM_IDENTIFIER }
      return json(test.state.current)
    }

    const result = await test.run()
    expect(result).toEqual({ confirmationRequired: test.state.current, ready: 0, operationIds: [] })
    expect(test.writes().map((call) => call.method)).toEqual(['PATCH'])
    expect(test.creates()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
    if (result.confirmationRequired === undefined) {
      throw new Error('Expected confirmed connection to be returned for a new user intent')
    }
    const confirmed = basicRoleIntent(result.confirmationRequired, test.state.database, test.state.tree)
    await expect(createBasicPostgresRoles(confirmed, {
      signal: new AbortController().signal, onStage: test.onStage, onOperation: test.onOperation, pollMs: 0, timeoutMs: 1000,
    })).resolves.toEqual({ ready: 0, operationIds: ['create-r_appdb', 'create-rw_appdb'] })
    expect(test.creates()).toHaveLength(2)
    expect(test.creates().map((call) => call.body.expected_target_identity)).toEqual([TARGET_IDENTITY, TARGET_IDENTITY])
  })

  it('blocks creation when a full discovery still cannot prove a cluster identity', async () => {
    const test = fixture({ fresh: true, topology: {} })

    await expect(test.run()).rejects.toThrow('Не удалось подтвердить идентичность PostgreSQL-кластера')
    expect(test.state.connectionReads).toBe(2)
    expect(test.writes().map((call) => call.method)).toEqual(['PATCH'])
    expect(test.creates()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
  })

  it.each(['updated_at', 'discovery_config'] as const)('does not overwrite a concurrent %s change', async (field) => {
    const test = fixture({ fresh: true })
    if (field === 'updated_at') test.state.current.updated_at = SAVED_VERSION
    else test.state.current.discovery_config = { unrelated_new_setting: true }
    await expect(test.run()).rejects.toThrow('чужие изменения не перезаписаны')
    expect(test.writes()).toEqual([])
  })

  it.each(['owner', 'schemas', 'name'] as const)('blocks changed database %s before either create', async (field) => {
    const test = fixture()
    if (field === 'owner') test.state.database.attributes = { owner: 'different_owner' }
    if (field === 'schemas') test.state.tree.push(schema('new_scope'))
    if (field === 'name') {
      test.state.database.name = 'renamed_db'
      test.state.tree[0].name = 'renamed_db'
    }
    await expect(test.run()).rejects.toThrow('Владелец или схемы базы изменились')
    expect(test.writes()).toEqual([])
  })

  it('blocks a database skipped during the post-save discovery', async () => {
    const test = fixture({ fresh: true })
    test.state.onRead = () => {
      if (test.state.connectionReads > 1) test.state.current.topology = {
        system_identifier: SYSTEM_IDENTIFIER, skipped_databases: [{ name: 'appdb', reason: 'unavailable' }],
      }
      return json(test.state.current)
    }
    await expect(test.run()).rejects.toThrow('не удалось обнаружить')
    expect(test.writes().map((call) => call.method)).toEqual(['PATCH'])
  })

  it.each([0, 1])('checks existing nonexact role %i before creating either member', async (index) => {
    const test = fixture()
    test.state.policies[index].observed_summary.role = { exists: true }
    await expect(test.run()).rejects.toThrow('Одноимённая роль уже существует')
    expect(test.creates()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
  })

  it('does not silently adopt an unmanaged exact existing role', async () => {
    const test = fixture()
    Object.assign(test.state.policies[1], { exact: true, status: 'unmanaged' })
    test.state.policies[1].observed_summary.role = { exists: true }
    await expect(test.run()).rejects.toThrow('Одноимённая роль уже существует')
    expect(test.creates()).toEqual([])
  })

  it('does not repair a managed but drifted existing role', async () => {
    const test = fixture()
    Object.assign(test.state.policies[1], { managed: true, exact: false, status: 'drift' })
    await expect(test.run()).rejects.toThrow('Одноимённая роль уже существует')
    expect(test.creates()).toEqual([])
  })

  it.each([0, 1, 2])('skips %i already managed and synced members', async (count) => {
    const test = fixture()
    for (const item of test.state.policies.slice(0, count)) {
      Object.assign(item, { managed: true, exact: true, status: 'synced' })
      item.observed_summary.role = { exists: true }
    }
    const result = await test.run()
    expect(test.creates()).toHaveLength(2 - count)
    expect(result.ready).toBe(count)
    expect(result.operationIds).toEqual(test.state.policies.slice(count).map((item) => `create-${item.desired_spec.role_name}`))
  })

  it('resumes persisted pending transitions by operation identity without re-enqueueing them', async () => {
    const test = fixture()
    Object.assign(test.state.policies[0], {
      transition_active: true, transition_operation_id: 'persisted-operation', status: 'pending',
    })
    const result = await test.run()
    expect(test.creates()).toHaveLength(1)
    expect(test.creates()[0].path).toContain(test.intent.selected[1].key)
    expect(test.onOperation).toHaveBeenCalledWith('r_appdb', 'persisted-operation')
    expect(result.operationIds).toEqual(['persisted-operation', 'create-rw_appdb'])
    expect(test.intent.requestIds.has(test.intent.selected[0].key)).toBe(false)
  })

  it('reuses both persisted transitions without any new mutation', async () => {
    const test = fixture()
    test.state.policies.forEach((item, index) => Object.assign(item, {
      transition_active: true, transition_operation_id: `persisted-${index}`, status: 'running',
    }))
    await expect(test.run()).resolves.toEqual({ ready: 0, operationIds: ['persisted-0', 'persisted-1'] })
    expect(test.writes()).toEqual([])
  })

  it.each([0, 1])('does not create a new operation when member %i has a failed owned transition', async (index) => {
    const test = fixture()
    Object.assign(test.state.policies[index], {
      transition_active: true, transition_operation_id: 'failed-operation', status: 'failed',
    })
    await expect(test.run()).rejects.toThrow(/новая операция не создаётся/i)
    expect(test.creates()).toEqual([])
    expect(test.intent.operations.get(test.state.policies[index].template_key)).toBe('failed-operation')
  })

  it.each([0, 1])('keeps the failed operation link for managed missing member %i even after transition ownership ends', async (index) => {
    const test = fixture()
    Object.assign(test.state.policies[index], {
      managed: true, exact: false, transition_active: false, transition_operation_id: 'previous-failed-operation', status: 'failed',
    })
    test.state.policies[index].observed_summary.role = { exists: false }

    await expect(test.run()).rejects.toThrow('Предыдущая операция')
    expect(test.creates()).toEqual([])
    expect(test.intent.requestIds.size).toBe(0)
    expect(test.intent.operations.get(test.state.policies[index].template_key)).toBe('previous-failed-operation')
    expect(test.onOperation).toHaveBeenCalledWith(test.state.policies[index].desired_spec.role_name, 'previous-failed-operation')
  })

  it('blocks an active transition without an operation identity', async () => {
    const test = fixture()
    Object.assign(test.state.policies[1], { transition_active: true, status: 'pending' })
    await expect(test.run()).rejects.toThrow('ещё выполняется')
    expect(test.creates()).toEqual([])
  })

  it('reconciles a lost PATCH response by reading back the exact catalog, without replaying the CAS', async () => {
    const test = fixture({ fresh: true })
    test.state.onPatch = (call) => {
      test.state.current = { ...test.state.current, updated_at: SAVED_VERSION, discovery_config: call.body.discovery_config }
      throw new TypeError('lost response')
    }
    await expect(test.run()).resolves.toEqual({ ready: 0, operationIds: ['create-r_appdb', 'create-rw_appdb'] })
    expect(test.writes().filter((call) => call.method === 'PATCH')).toHaveLength(1)
    expect(test.state.connectionReads).toBe(2)
    expect(test.creates()).toHaveLength(2)
  })

  it('stops if lost PATCH readback does not contain the intended catalog', async () => {
    const test = fixture({ fresh: true })
    test.state.onPatch = () => { throw new TypeError('lost response') }
    await expect(test.run()).rejects.toThrow('сеть недоступна')
    expect(test.state.connectionReads).toBe(2)
    expect(test.writes().filter((call) => call.method === 'PATCH')).toHaveLength(1)
    expect(test.creates()).toEqual([])
  })

  it('keeps the same request ID after a lost first create response and does not enqueue the second until retry', async () => {
    const test = fixture()
    let loseFirst = true
    test.state.onCreate = (index) => {
      if (index === 0 && loseFirst) { loseFirst = false; throw new TypeError('lost response') }
      return json({ operation_id: `create-${index}` }, 202)
    }
    await expect(test.run()).rejects.toThrow('сеть недоступна')
    expect(test.creates()).toHaveLength(1)
    const firstRequestId = test.creates()[0].body.request_id
    expect(test.intent.requestIds.get(test.intent.selected[0].key)).toBe(firstRequestId)
    expect(test.intent.operations.size).toBe(0)

    await expect(test.run()).resolves.toEqual({ ready: 0, operationIds: ['create-0', 'create-1'] })
    expect(test.creates()).toHaveLength(3)
    expect(test.creates()[1].body.request_id).toBe(firstRequestId)
    expect(test.creates()[2].body.request_id).not.toBe(firstRequestId)
  })

  it('recovers a lost first response via its persisted transition before creating the second member', async () => {
    const test = fixture()
    test.state.onCreate = (index) => {
      if (index === 0) {
        Object.assign(test.state.policies[0], { transition_active: true, transition_operation_id: 'persisted-first', status: 'pending' })
        throw new TypeError('lost response')
      }
      return json({ operation_id: 'second-operation' }, 202)
    }
    await expect(test.run()).rejects.toThrow('сеть недоступна')
    expect(test.creates()).toHaveLength(1)
    await expect(test.run()).resolves.toEqual({ ready: 0, operationIds: ['persisted-first', 'second-operation'] })
    expect(test.creates()).toHaveLength(2)
    expect(test.creates()[1].path).toContain(test.intent.selected[1].key)
  })

  it('retains the successful first operation and second request identity when the second creation fails', async () => {
    const test = fixture()
    test.state.onCreate = (index) => index === 0
      ? json({ operation_id: 'first-operation' }, 202) : json({ error: 'second member rejected' }, 409)
    await expect(test.run()).rejects.toThrow('second member rejected')
    expect(test.creates()).toHaveLength(2)
    expect([...test.intent.operations]).toEqual([[test.intent.selected[0].key, 'first-operation']])
    expect(test.intent.requestIds.get(test.intent.selected[1].key)).toBe(test.creates()[1].body.request_id)
    expect(test.onOperation).toHaveBeenCalledWith('r_appdb', 'first-operation')
  })

  it('honors abort before any reads or mutations', async () => {
    const test = fixture({ fresh: true })
    const controller = new AbortController()
    controller.abort()
    await expect(test.run({ signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' })
    expect(test.state.calls).toEqual([])
  })

  it('honors abort between checking and PATCH', async () => {
    const test = fixture({ fresh: true })
    const controller = new AbortController()
    await expect(test.run({ signal: controller.signal, onStage: (stage) => { if (stage === 'saving') controller.abort() } }))
      .rejects.toMatchObject({ name: 'AbortError' })
    expect(test.writes()).toEqual([])
  })

  it('keeps the first operation but never creates the second after abort', async () => {
    const test = fixture()
    const controller = new AbortController()
    await expect(test.run({
      signal: controller.signal,
      onOperation: (label) => { if (label === 'r_appdb') controller.abort() },
    })).rejects.toMatchObject({ name: 'AbortError' })
    expect(test.creates()).toHaveLength(1)
    expect(test.intent.operations.get(test.intent.selected[0].key)).toBe('create-r_appdb')
  })

  it('does not reconcile or start another mutation after an aborted PATCH request', async () => {
    const test = fixture({ fresh: true })
    const controller = new AbortController()
    test.state.onPatch = () => { controller.abort(); throw new DOMException('Operation aborted', 'AbortError') }
    await expect(test.run({ signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' })
    expect(test.state.connectionReads).toBe(1)
    expect(test.creates()).toEqual([])
  })

  it('reports a policy blocker before creating either role', async () => {
    const test = fixture()
    Object.assign(test.state.policies[1], { apply_supported: false, blocked_reason: 'superuser_required' })
    await expect(test.run()).rejects.toThrow('Создание роли заблокировано проверкой базы')
    expect(test.creates()).toEqual([])
  })

  it('fails closed on an old backend or connector without create-only capability', async () => {
    const test = fixture()
    test.state.current.capabilities = ['discover', 'role.policy.apply']
    await expect(test.run()).rejects.toThrow('Обновите компоненты')
    expect(test.creates()).toEqual([])
    expect(test.writes().some((call) => call.path.endsWith('/apply'))).toBe(false)
  })

  it.each([
    { observed_fingerprint: '' }, { apply_supported: false }, { blocked_reason: 'database_read_only' },
  ])('checks both policy guards before creating either member %#', async (change) => {
    const test = fixture()
    Object.assign(test.state.policies[1], change)
    await expect(test.run()).rejects.toThrow('заблокировано проверкой базы')
    expect(test.creates()).toEqual([])
  })

  it.each(['missing', 'duplicate', 'spec'] as const)('blocks %s policy confirmation before mutation', async (change) => {
    const test = fixture()
    if (change === 'missing') test.state.policies.pop()
    if (change === 'duplicate') test.state.policies.push(structuredClone(test.state.policies[1]))
    if (change === 'spec') test.state.policies[1].desired_spec.schemas = ['different_scope']
    await expect(test.run()).rejects.toThrow('не подтвердила настройки обеих ролей')
    expect(test.creates()).toEqual([])
  })

  it('times out without create jobs while discovery remains active', async () => {
    const test = fixture()
    test.state.current.status = 'discovering'
    await expect(test.run({ pollMs: 0, timeoutMs: 0 })).rejects.toThrow('Синхронизация ещё выполняется')
    expect(test.writes()).toEqual([])
    expect(test.state.connectionReads).toBe(1)
  })

  it('blocks a catalog changed while discovery is running', async () => {
    const test = fixture()
    test.state.current.status = 'discovering'
    test.state.onRead = () => {
      if (test.state.connectionReads > 1) {
        test.state.current.status = 'active'
        test.state.current.discovery_config = { other: 'concurrent-change' }
      }
      return json(test.state.current)
    }
    await expect(test.run()).rejects.toThrow('Каталог изменился во время синхронизации')
    expect(test.writes()).toEqual([])
  })

  it('does not queue role jobs when catalog discovery ends in failure', async () => {
    const test = fixture()
    test.state.current.status = 'discovery_failed'
    await expect(test.run()).rejects.toThrow('Подключение не готово к созданию ролей')
    expect(test.writes()).toEqual([])
  })
})
