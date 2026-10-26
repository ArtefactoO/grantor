import { useId, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type { Account, Connection } from '../lib/types'
import { Field, Input, Button, Spinner } from '@project/ui'

export interface DatabaseOwnerCandidate {
  id: string
  identity: string
  roleOid: number
  kind: string
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {}
}

export function useDatabaseOwnerInventory(connection: Connection, enabled: boolean) {
  const query = useQuery({
    queryKey: [...qk.connectionAccounts(connection.id), 'database-owners'],
    queryFn: async ({ signal }) => {
      const data = await api<{ accounts?: unknown }>(`/api/v1/connections/${connection.id}/accounts`, { signal })
      if (!Array.isArray(data.accounts) || data.accounts.some((item: unknown) => {
        const account = record(item)
        return typeof account.id !== 'string' || typeof account.connection_id !== 'string' ||
          typeof account.kind !== 'string' || typeof account.status !== 'string' ||
          typeof account.engine_identity !== 'string'
      })) throw new Error('Account inventory is unavailable')
      return data.accounts as Account[]
    },
    enabled: enabled && connection.engine === 'postgres',
    retry: false,
    staleTime: 0,
  })
  const candidates = useMemo(() => {
    const config = record(connection.discovery_config)
    const allowed = Array.isArray(config.database_create_owners)
      ? config.database_create_owners.filter((item): item is string => typeof item === 'string') : []
    return (query.data ?? []).flatMap((account): DatabaseOwnerCandidate[] => {
      const attributes = record(account.attributes)
      const oid = attributes.role_oid
      // An omitted SUPERUSER flag is unknown, not evidence of NOSUPERUSER.
      if (account.connection_id !== connection.id || account.status !== 'active' ||
        !['login', 'group'].includes(account.kind) || typeof account.engine_identity !== 'string' ||
        attributes.superuser !== false || typeof oid !== 'number' || !Number.isInteger(oid) ||
        oid <= 0 || oid > 4294967295 ||
        (allowed.length > 0 && !allowed.includes(account.engine_identity))) return []
      return [{ id: account.id, identity: account.engine_identity, roleOid: oid, kind: account.kind }]
    }).sort((a, b) => a.identity.localeCompare(b.identity))
  }, [connection.id, connection.discovery_config, query.data])
  return { query, candidates }
}

export function DatabaseOwnerField({
  value, onChange, selection, candidates, loading, failed, disabled, createDefaultRoles,
}: {
  value: string
  onChange: (value: string, candidate: DatabaseOwnerCandidate | null) => void
  selection: DatabaseOwnerCandidate | null
  candidates: DatabaseOwnerCandidate[]
  loading: boolean
  failed: boolean
  disabled: boolean
  createDefaultRoles: boolean
}) {
  const id = useId()
  const [searchOpen, setSearchOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const matching = candidates.filter((candidate) => candidate.identity.toLocaleLowerCase().includes(value.toLocaleLowerCase()))
  const visible = matching.slice(0, 8)
  const select = (candidate: DatabaseOwnerCandidate) => {
    // The API identifier is data. Never derive it from a label or trim it.
    onChange(candidate.identity, candidate)
    setSearchOpen(false)
  }
  const searchVisible = searchOpen && selection === null && !disabled && !loading && !failed
  return (
    <div className="space-y-2" onBlur={(event) => {
      if (!event.currentTarget.contains(event.relatedTarget)) setSearchOpen(false)
    }}>
      <Field label="Владелец" htmlFor={id} hint={createDefaultRoles
        ? 'Существующая роль без SUPERUSER. От неё будут настроены права на будущие объекты.'
        : 'Существующая роль без SUPERUSER, которая станет владельцем базы.'}>
        <Input id={id} value={value} required disabled={disabled}
          role="combobox" aria-autocomplete="list" aria-expanded={searchVisible}
          aria-controls={searchVisible ? `${id}-roles` : undefined}
          aria-activedescendant={searchVisible && visible.length > 0 ? `${id}-role-${activeIndex}` : undefined}
          aria-describedby={`${id}-status`}
          placeholder="Найти роль или ввести точное имя" className="font-mono text-[13px]"
          autoComplete="off"
          onFocus={() => setSearchOpen(true)}
          onChange={(event) => { onChange(event.target.value, null); setActiveIndex(0); setSearchOpen(true) }}
          onKeyDown={(event) => {
            if (event.key === 'Escape' && searchOpen) { event.preventDefault(); event.stopPropagation(); setSearchOpen(false) }
            if (!searchVisible || visible.length === 0) return
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
              event.preventDefault()
              setActiveIndex((index) => (index + (event.key === 'ArrowDown' ? 1 : -1) + visible.length) % visible.length)
            } else if (event.key === 'Enter') {
              event.preventDefault()
              select(visible[Math.min(activeIndex, visible.length - 1)])
            }
          }}
        />
      </Field>
      {searchVisible && visible.length > 0 && (
        <ul id={`${id}-roles`} role="listbox" aria-label="Существующие владельцы" className="max-h-52 overflow-y-auto rounded-md border border-line bg-panel2 p-1">
          {visible.map((candidate, index) => (
            <li key={candidate.id} role="presentation">
              <button id={`${id}-role-${index}`} type="button" role="option" aria-selected={index === activeIndex}
                onMouseDown={(event) => event.preventDefault()} onClick={() => select(candidate)}
                className="flex min-h-11 w-full flex-wrap items-center justify-between gap-x-3 rounded-sm px-2 py-2 text-left text-sm text-text hover:bg-accent-soft focus-visible:outline-2 focus-visible:outline-accent aria-selected:bg-accent-soft">
                <span className="min-w-0 break-all whitespace-pre-wrap font-mono">{candidate.identity}</span>
                <span className="text-xs text-muted">{candidate.kind === 'group' ? 'Роль NOLOGIN' : 'Учётная запись LOGIN'}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <div id={`${id}-status`} role="status" className="text-xs leading-relaxed text-muted">
        {selection !== null ? (
          <span>Выбрана существующая {selection.kind === 'group' ? 'роль NOLOGIN' : 'учётная запись LOGIN'}.</span>
        ) : loading ? (
          <span className="inline-flex items-center gap-1.5"><Spinner className="size-3" />Загружаем роли подключения. Можно ввести точное имя вручную.</span>
        ) : failed ? (
          <span>Список ролей недоступен. Введите точное имя существующей роли вручную; сервер проверит владельца.</span>
        ) : candidates.length === 0 ? (
          <span>В снимке нет подтверждённых кандидатов. Введите точное имя вручную или синхронизируйте подключение.</span>
        ) : searchVisible && matching.length === 0 ? (
          <span>Роль не найдена в снимке. Можно оставить точное имя для проверки сервером.</span>
        ) : (
          <span>Поиск по снимку подключения. Сервер проверит владельца и ограничения перед созданием.</span>
        )}
      </div>
      {selection !== null && !disabled && (
        <Button variant="ghost" size="sm" onClick={() => { onChange(value, null); setSearchOpen(true) }}>
          Выбрать другую роль
        </Button>
      )}
    </div>
  )
}
