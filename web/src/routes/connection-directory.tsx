import { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { Cable, ChevronDown, ChevronLeft, ChevronRight, Clock3, Database, Layers3, Star } from '@project/ui/icons'
import { Button, cn, DirectorySectionHeader, EmptyState, ErrorBanner, ErrorState, IconButton, SearchInput, Spinner, Tooltip } from '@project/ui'
import { EngineBadge, StatusChip } from '../components/ui/badge'
import { SegmentedFilter, SelectionSelect } from '../components/ui/selection-chips'
import { ConnectionSyncButton } from '../components/connection-sync-button'
import { ALL_CONNECTION_FACETS, catalogPage, connectionCatalog, connectionFacetOptions, DEFAULT_CATALOG_STATE, restoreCatalogState } from '../lib/connection-catalog'
import type { CatalogState, ConnectionFacetOption } from '../lib/connection-catalog'
import { connectionEngineLabel, connectionEnvironmentLabel, connectionNeedsAttention, formatCompactRelative, shortServerVersion } from '../lib/connection-presentation'
import type { ConnectionListFilter } from '../lib/connection-presentation'
import { errorMessage } from '../lib/errorMessage'
import { connectionStatusTone, driftTotal } from '../lib/status'
import { formatDateTime } from '../lib/time'
import type { Connection } from '../lib/types'
import { connectionStatusLabel, connectionSyncLabel } from '../lib/ui-copy'
import { useConnectionFavorites } from '../lib/use-connection-favorites'

export { ALL_CONNECTION_FACETS, connectionFacetOptions } from '../lib/connection-catalog'
export type { ConnectionFacetOption } from '../lib/connection-catalog'

/** Keep dependent engine counts scoped to the selected environment. */
export function useConnectionFacetFilters(connections: Connection[]) {
  const [environment, setEnvironment] = useState(ALL_CONNECTION_FACETS)
  const [engine, setEngine] = useState(ALL_CONNECTION_FACETS)
  const all = useMemo(() => connectionFacetOptions(connections), [connections])
  const facets = useMemo(() => ({
    environments: all.environments,
    engines: connectionFacetOptions(connections.filter(c => environment === ALL_CONNECTION_FACETS || connectionEnvironmentLabel(c.environment) === environment)).engines,
  }), [all.environments, connections, environment])
  useEffect(() => {
    if (environment !== ALL_CONNECTION_FACETS && !all.environments.some(o => o.value === environment)) setEnvironment(ALL_CONNECTION_FACETS)
    if (engine !== ALL_CONNECTION_FACETS && !facets.engines.some(o => o.value === engine)) setEngine(ALL_CONNECTION_FACETS)
  }, [all.environments, engine, environment, facets.engines])
  return { facets, environment, setEnvironment, engine, setEngine }
}

export interface ConnectionDirectoryProps {
  connections: Connection[]
  pending: boolean
  error: boolean
  onRetry: () => void
  canRefresh: boolean
  stateKey?: string
}

export function ConnectionDirectory({ connections, pending, error, onRetry, canRefresh, stateKey }: ConnectionDirectoryProps) {
  const storageKey = stateKey === undefined ? null : `grantor:connection-catalog:${stateKey}`
  const [state, setState] = useState<CatalogState>(() => {
    try { return restoreCatalogState(storageKey === null ? null : sessionStorage.getItem(storageKey)) }
    catch { return restoreCatalogState(null) }
  })
  const favorites = useConnectionFavorites()
  const directoryRef = useRef<HTMLElement>(null)
  const favoriteFocusRef = useRef<string | null>(null)
  const catalog = useMemo(() => connectionCatalog(connections, favorites.ids, state), [connections, favorites.ids, state])
  useEffect(() => {
    const id = favoriteFocusRef.current
    if (id === null || favorites.mutation.isPending) return
    favoriteFocusRef.current = null
    const active = document.activeElement
    if (active !== document.body && !(active instanceof HTMLElement && active.dataset.favoriteId === id)) return
    const buttons = directoryRef.current?.querySelectorAll<HTMLButtonElement>('[data-favorite-id]') ?? []
    const target = [...buttons].find(button => button.dataset.favoriteId === id && !button.disabled && button.closest('[hidden]') === null)
    // Moving between sections remounts a row. A hidden destination must not
    // take keyboard focus; search remains a stable recovery point.
    const fallback = directoryRef.current?.querySelector<HTMLInputElement>('[aria-label="Поиск подключений"]')
    const focusTarget = target ?? fallback
    focusTarget?.focus()
  }, [favorites.ids, favorites.mutation.isPending])
  useEffect(() => {
    if (storageKey === null) return
    try { sessionStorage.setItem(storageKey, JSON.stringify(state)) } catch { /* View state remains usable without storage. */ }
  }, [state, storageKey])
  useEffect(() => {
    if (pending || error || connections.length === 0) return
    const all = connectionFacetOptions(connections)
    setState(current => {
      const environment = current.environment === ALL_CONNECTION_FACETS || all.environments.some(o => o.value === current.environment) ? current.environment : ALL_CONNECTION_FACETS
      const engine = current.engine === ALL_CONNECTION_FACETS || all.engines.some(o => o.value === current.engine) ? current.engine : ALL_CONNECTION_FACETS
      return environment === current.environment && engine === current.engine ? current : { ...current, environment, engine, pages: {} }
    })
  }, [connections, error, pending])
  const change = (patch: Partial<CatalogState>) => setState(current => ({ ...current, ...patch, pages: {}, expanded: {} }))
  const reset = () => setState({ ...DEFAULT_CATALOG_STATE, expanded: {}, pages: {} })
  const open = (key: string, fallback: boolean) => state.expanded[key] ?? fallback
  const toggle = (key: string, fallback: boolean) => setState(current => ({ ...current, expanded: { ...current.expanded, [key]: !(current.expanded[key] ?? fallback) } }))
  const setPage = (key: string, page: number) => setState(current => ({ ...current, pages: { ...current.pages, [key]: page } }))
  const row = (connection: Connection) => (
    <ConnectionListRow key={connection.id} connection={connection} canRefresh={canRefresh}
      favorite={favorites.ids.has(connection.id)}
      favoriteDisabled={!favorites.query.isSuccess || favorites.mutation.isPending}
      favoriteBusy={favorites.mutation.isPending && favorites.mutation.variables?.id === connection.id}
      onFavorite={() => {
        const active = document.activeElement
        favoriteFocusRef.current = active instanceof HTMLElement && active.dataset.favoriteId === connection.id ? connection.id : null
        favorites.mutation.mutate({ id: connection.id, favorite: !favorites.ids.has(connection.id) })
      }} />
  )
  const pagedRows = (items: Connection[], key: string, label: string) => {
    const page = catalogPage(items, state.pages[key] ?? 1, state.pageSize)
    return <>
      <div className="divide-y divide-line/70">{page.items.map(row)}</div>
      {page.pageCount > 1 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-muted" aria-label={`Страницы: ${label}`}>
          <span aria-live="polite" className="tabular-nums">{page.start}–{page.end} из {page.total}</span>
          <div className="flex items-center gap-1">
            <IconButton label={`Предыдущая страница: ${label}`} icon={<ChevronLeft className="size-4" />} disabled={page.page === 1} onClick={() => setPage(key, page.page - 1)} />
            <span className="min-w-10 text-center tabular-nums">{page.page} / {page.pageCount}</span>
            <IconButton label={`Следующая страница: ${label}`} icon={<ChevronRight className="size-4" />} disabled={page.page === page.pageCount} onClick={() => setPage(key, page.page + 1)} />
          </div>
        </div>
      )}
    </>
  }
  const revealMatches = state.search.trim() !== '' || state.engine !== ALL_CONNECTION_FACETS
  return (
    <section ref={directoryRef} id="connections" aria-labelledby="connections-title" className="min-w-0 overflow-hidden rounded-[10px] border border-line bg-panel">
      <div className="flex h-11 items-center gap-2 border-b border-line px-3">
        <Cable className="size-4 text-muted" aria-hidden="true" />
        <h2 id="connections-title" className="text-sm font-medium">Подключения</h2>
        <span className="text-xs tabular-nums text-muted">{connections.length}</span>
      </div>
      {error ? <div className="p-4"><ErrorState message="Не удалось загрузить подключения" onRetry={onRetry} /></div>
        : pending ? <div className="flex justify-center py-12"><Spinner /></div>
        : connections.length === 0 ? <div className="p-4"><EmptyState icon={Cable} title="Подключений пока нет" description="Добавьте первое подключение, чтобы Grantor выполнил discovery ресурсов и аккаунтов." /></div>
        : <>
          <ConnectionListControls search={state.search} onSearchChange={search => change({ search })}
            filter={state.filter} onFilterChange={filter => change({ filter })} counts={catalog.statusCounts}
            environments={catalog.environments} environment={state.environment} onEnvironmentChange={environment => change({ environment, engine: ALL_CONNECTION_FACETS })}
            engines={catalog.engines} engine={state.engine} onEngineChange={engine => change({ engine })}
            showEngineFilter={connectionFacetOptions(connections).engines.length > 1}
            favoritesOnly={state.favoritesOnly} onFavoritesOnlyChange={favoritesOnly => change({ favoritesOnly })} modeCounts={catalog.modeCounts} />
          {favorites.query.isError && <div className="p-3"><ErrorBanner>
            Избранное недоступно. <Button variant="ghost" size="sm" onClick={() => void favorites.query.refetch()}>Повторить</Button>
          </ErrorBanner></div>}
          {favorites.mutation.isError && <div className="px-3 pt-3"><ErrorBanner>Не удалось сохранить избранное: {errorMessage(favorites.mutation.error)}</ErrorBanner></div>}
          {catalog.total === 0 ? <div className="space-y-3 px-4 py-10 text-center text-sm text-muted" role="status">
            <p>{state.favoritesOnly && catalog.modeCounts.all > 0 ? 'В избранном пока нет подходящих подключений.' : 'Подключения не найдены.'}</p>
            <Button variant="outline" size="sm" onClick={reset}>Сбросить фильтры</Button>
          </div> : <>
            {catalog.favoriteConnections.length > 0 && <section aria-label="Избранные подключения">
              <DirectorySectionHeader label="Избранное" count={catalog.favoriteConnections.length} />
              {pagedRows(catalog.favoriteConnections, 'favorites', 'Избранное')}
            </section>}
            {catalog.groups.length > 0 && <>
              {catalog.favoriteConnections.length > 0 && <DirectorySectionHeader label="Остальные подключения" count={catalog.total - catalog.favoriteConnections.length} />}
              {catalog.groups.map((group, groupIndex) => {
                const key = `environment:${group.key}`
                const expanded = revealMatches || state.environment !== ALL_CONNECTION_FACETS || groupIndex === 0
                return <CatalogDisclosure key={key} label={group.label} icon={<Layers3 className="size-4" aria-hidden="true" />} count={group.connections.length} open={open(key, expanded)} onToggle={() => toggle(key, expanded)}>
                  {group.engines.map((engine, engineIndex) => {
                    const engineKey = `${key}:engine:${engine.value}`
                    const engineExpanded = revealMatches || (groupIndex === 0 && engineIndex === 0)
                    return <CatalogDisclosure key={engineKey} label={engine.label} icon={<Database className="size-3.5" aria-hidden="true" />} count={engine.count} open={open(engineKey, engineExpanded)} onToggle={() => toggle(engineKey, engineExpanded)} nested>
                      {pagedRows(engine.connections, engineKey, `${group.label} · ${engine.label}`)}
                    </CatalogDisclosure>
                  })}
                </CatalogDisclosure>
              })}
            </>}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-3 py-2 text-xs text-muted">
              <span role="status" className="tabular-nums">Найдено: {catalog.total}</span>
              <SelectionSelect label="Подключений на странице группы" value={String(state.pageSize)} inactiveValue="20" options={[{ value: '20', label: '20 на странице' }, { value: '50', label: '50 на странице' }]} onChange={value => setState(current => ({ ...current, pageSize: Number(value), pages: {} }))} />
            </div>
          </>}
        </>}
    </section>
  )
}

function CatalogDisclosure({ label, icon, count, open, onToggle, nested = false, children }: {
  label: string; icon: ReactNode; count: number; open: boolean; onToggle: () => void; nested?: boolean; children: ReactNode
}) {
  const id = useId()
  return <section className={nested ? 'min-w-0 pl-2 sm:pl-4' : 'min-w-0 border-t border-line'} aria-label={nested ? `Движок ${label}` : `Окружение ${label}`}>
    <button type="button" aria-label={`${label} ${count}`} aria-expanded={open} aria-controls={id} onClick={onToggle}
      className="grantor-touch-target ui-control-feedback flex min-h-10 w-full items-center gap-2 px-3 py-2 text-left text-xs text-muted hover:bg-panel2 hover:text-text focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-accent">
      <ChevronDown className={cn('size-3.5 shrink-0', !open && '-rotate-90')} aria-hidden="true" />
      {icon}<span className="min-w-0 flex-1 truncate font-medium">{label}</span><span className="tabular-nums">{count}</span>
    </button>
    <div id={id} hidden={!open}>{children}</div>
  </section>
}

export function ConnectionListControls({ search, onSearchChange, filter, onFilterChange, counts, environments, environment, onEnvironmentChange, engines, engine, onEngineChange, favoritesOnly = false, onFavoritesOnlyChange, modeCounts, showEngineFilter = false }: {
  search: string; onSearchChange: (value: string) => void
  filter: ConnectionListFilter; onFilterChange: (value: ConnectionListFilter) => void
  counts: Record<ConnectionListFilter, number>
  environments: ConnectionFacetOption[]; environment: string; onEnvironmentChange: (value: string) => void
  engines: ConnectionFacetOption[]; engine: string; onEngineChange: (value: string) => void
  favoritesOnly?: boolean; onFavoritesOnlyChange?: (value: boolean) => void
  modeCounts?: { all: number; favorites: number }; showEngineFilter?: boolean
}) {
  return <div className="space-y-3 border-b border-line p-3">
    <div className="flex flex-wrap items-center gap-2">
      <div className="min-w-0 basis-full sm:min-w-56 sm:flex-1"><SearchInput value={search} onChange={onSearchChange} placeholder="Название, тип или окружение" ariaLabel="Поиск подключений" /></div>
      <ConnectionFacetFilters environments={environments} environment={environment} onEnvironmentChange={onEnvironmentChange} engines={engines} engine={engine} onEngineChange={onEngineChange} showEngines={showEngineFilter} />
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2">
      {onFavoritesOnlyChange !== undefined && <SegmentedFilter label="Режим каталога" value={favoritesOnly ? 'favorites' : 'all'} onChange={mode => onFavoritesOnlyChange(mode === 'favorites')} options={[
        { value: 'all', label: 'Все', count: modeCounts?.all },
        { value: 'favorites', label: <span className="inline-flex items-center gap-1"><Star className="size-3" aria-hidden="true" />Избранное</span>, accessibleLabel: 'Избранное', count: modeCounts?.favorites },
      ]} />}
      <SelectionSelect label="Состояние подключения" value={filter} inactiveValue="all" onChange={value => onFilterChange(value as ConnectionListFilter)} options={[
        { value: 'all', label: 'Любое состояние', count: counts.all },
        { value: 'synced', label: 'Sync', count: counts.synced },
        { value: 'error', label: 'Error', count: counts.error },
      ]} />
    </div>
  </div>
}

export function ConnectionFacetFilters({ className, environments, environment, onEnvironmentChange, engines, engine, onEngineChange, showEngines = false }: {
  className?: string; total?: number; environments: ConnectionFacetOption[]; environment: string; onEnvironmentChange: (value: string) => void
  engines: ConnectionFacetOption[]; engine: string; onEngineChange: (value: string) => void; showEngines?: boolean
}) {
  const engineOptions = engines.some(option => option.value === engine) || engine === ALL_CONNECTION_FACETS ? engines : [...engines, { value: engine, label: connectionEngineLabel(engine), count: 0 }]
  return <div className={cn('flex min-w-0 flex-wrap items-center gap-1.5', className)}>
    {(environments.length > 1 || environment !== ALL_CONNECTION_FACETS) && <SelectionSelect label="Окружение подключения" value={environment} onChange={onEnvironmentChange} inactiveValue={ALL_CONNECTION_FACETS} icon={<Layers3 className="size-3.5" aria-hidden="true" />} options={[
      { value: ALL_CONNECTION_FACETS, label: 'All environments', count: environments.length },
      ...environments.map(({ value, label }) => ({ value, label })),
    ]} />}
    {(showEngines || engines.length > 1 || engine !== ALL_CONNECTION_FACETS) && <SelectionSelect label="Движок подключения" value={engine} onChange={onEngineChange} inactiveValue={ALL_CONNECTION_FACETS} icon={<Database className="size-3.5" aria-hidden="true" />} options={[
      { value: ALL_CONNECTION_FACETS, label: 'All engines', count: engines.reduce((sum, option) => sum + option.count, 0) }, ...engineOptions,
    ]} />}
  </div>
}

function ConnectionListRow({ connection, canRefresh, favorite, favoriteDisabled, favoriteBusy, onFavorite }: {
  connection: Connection; canRefresh: boolean; favorite: boolean; favoriteDisabled: boolean; favoriteBusy: boolean; onFavorite: () => void
}) {
  const drift = driftTotal(connection.drift)
  const [confirmedDiscoveryAt, setConfirmedDiscoveryAt] = useState<string | null>(null)
  const discoveryAt = confirmedDiscoveryAt ?? connection.last_discovery_at
  return <div className="grid min-h-14 grid-cols-[auto_minmax(0,1fr)] items-center gap-x-2 gap-y-1 border-t border-line/70 px-2 py-2 hover:bg-panel2/70 sm:flex sm:gap-2 sm:px-3">
    <IconButton label={`${favorite ? 'Убрать из избранного' : 'Добавить в избранное'}: ${connection.display_name}`} data-favorite-id={connection.id} icon={favoriteBusy ? <Spinner className="size-3.5" /> : <Star className={cn('size-4', favorite && 'fill-current text-accent')} />} aria-pressed={favorite} busy={favoriteBusy} disabled={favoriteDisabled} onClick={onFavorite} />
    <Link to="/connections/$connectionId" params={{ connectionId: connection.id }} className="grantor-touch-target flex min-w-0 flex-1 items-center gap-2.5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
      <span className="hidden shrink-0 sm:inline-flex"><EngineBadge engine={connection.engine} /></span>
      <span className="min-w-0 flex-1">
        <span className="block font-mono text-[13px] font-medium leading-snug [overflow-wrap:anywhere]">{connection.display_name}</span>
        <span className="block text-[11px] text-muted [overflow-wrap:anywhere]">{connectionEnvironmentLabel(connection.environment)} · {connectionEngineLabel(connection.engine)}{connection.server_version !== '' ? ` ${shortServerVersion(connection.server_version)}` : ''}{connection.tags.length > 0 ? ` · ${connection.tags.join(', ')}` : ''}</span>
        {connection.auth_mode === 'none' && <span className="block text-[11px] text-warn">Без парольной авторизации</span>}
      </span>
      <span className="hidden shrink-0 sm:inline-flex"><StatusChip tone={connectionStatusTone(connection.status)}>{connectionStatusLabel(connection.status)}</StatusChip></span>
      <span className="hidden shrink-0 md:inline-flex"><StatusChip tone={drift > 0 ? 'warn' : 'ok'}>{connectionSyncLabel(drift)}</StatusChip></span>
    </Link>
    <div className="col-start-2 flex shrink-0 items-center gap-2 sm:gap-1">
      <Tooltip content={`Последний успешный снимок кластера: ${formatDateTime(discoveryAt)}`} disabledTarget>
        <span className={cn('hidden w-[4.75rem] items-center justify-end gap-1 text-xs tabular-nums sm:inline-flex', connectionNeedsAttention(connection) ? 'text-warn' : 'text-muted')}><Clock3 className="size-3.5 shrink-0" aria-hidden="true" />{formatCompactRelative(discoveryAt)}</span>
      </Tooltip>
      <StatusChip tone={connectionStatusTone(connection.status)} className="sm:hidden">{connectionStatusLabel(connection.status)}</StatusChip>
      {canRefresh && <ConnectionSyncButton connectionId={connection.id} connectionName={connection.display_name} disabled={connection.status === 'disabled'} onSuccess={() => setConfirmedDiscoveryAt(new Date().toISOString())} />}
    </div>
  </div>
}
