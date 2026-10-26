// Боковая навигация control plane. Подписи разделов остаются видимыми на
// desktop и mobile: плотная панель не требует режима «только иконки».
import { useEffect, useState } from 'react'
import type { RefObject } from 'react'
import { Link, useRouterState } from '@tanstack/react-router'
import {
  Activity,
  Cable,
  LayoutDashboard,
  Users,
} from '@project/ui/icons'
import { cn, selectionSurfaceClassName } from '@project/ui'
import {
  connectionFromLocation,
  connectionSearchForRoute,
  useConnectionScope,
} from '../../lib/connection-context'

const BRAND_LOGOS = import.meta.glob('../../assets/brand/logo*.{svg,png}', {
  eager: true,
  import: 'default',
  query: '?url',
}) as Record<string, string>

function brandLogo(name: string): string | undefined {
  const hit = Object.entries(BRAND_LOGOS).find(([path]) => path.includes(`/${name}.`))
  return hit?.[1]
}

const CUSTOM_LOGO = brandLogo('logo')
const CUSTOM_LOGO_DARK = brandLogo('logo-dark') ?? CUSTOM_LOGO
const CUSTOM_LOGO_LIGHT = brandLogo('logo-light') ?? CUSTOM_LOGO

const NAV_ITEMS = [
  { to: '/overview', label: 'Обзор', icon: LayoutDashboard },
  { to: '/principals', label: 'Пользователи', icon: Users },
  { to: '/control', label: 'Контроль', icon: Activity },
] as const

function isRouteActive(to: (typeof NAV_ITEMS)[number]['to'], pathname: string): boolean {
  return pathname === to || pathname.startsWith(`${to}/`)
}

const NAV_ITEM_INTERACTION =
  'grantor-touch-target rounded-[7px] transition-colors duration-150 motion-reduce:transition-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent'
const LAST_CONNECTION_STORAGE_KEY = 'grantor:last-connection-id'
const LAST_CONNECTION_NAME_STORAGE_KEY = 'grantor:last-connection-name'

function storedConnectionValue(key: string): string | undefined {
  try {
    return window.sessionStorage.getItem(key) ?? undefined
  } catch {
    return undefined
  }
}

export interface SidebarProps {
  mobile?: boolean
  onNavigate?: () => void
  initialFocusRef?: RefObject<HTMLAnchorElement | null>
}

export function Sidebar({
  mobile = false,
  onNavigate,
  initialFocusRef,
}: SidebarProps = {}) {
  const location = useRouterState({ select: (s) => s.location })
  const pathname = location.pathname
  const locationConnection = connectionFromLocation(pathname, location.search)
  const [rememberedConnection, setRememberedConnection] = useState<string | undefined>(
    () => locationConnection ?? storedConnectionValue(LAST_CONNECTION_STORAGE_KEY),
  )
  const [rememberedConnectionName, setRememberedConnectionName] = useState<
    string | undefined
  >(() => storedConnectionValue(LAST_CONNECTION_NAME_STORAGE_KEY))

  useEffect(() => {
    if (locationConnection === undefined) return
    setRememberedConnection(locationConnection)
    try {
      window.sessionStorage.setItem(LAST_CONNECTION_STORAGE_KEY, locationConnection)
    } catch {
      // Navigation still works for the current route when browser storage is unavailable.
    }
  }, [locationConnection])

  const activeConnection = locationConnection ?? rememberedConnection
  const connectionScope = useConnectionScope(activeConnection, false)
  const resolvedConnectionName =
    connectionScope.resolution.kind === 'selected'
      ? connectionScope.resolution.connection.display_name
      : undefined
  // Запомненное подключение исчезло: его удалили или база пересоздана.
  // Отличать от «ещё грузится» обязательно по успешно загруженному списку,
  // иначе на первом рендере мы бы стирали память при каждой перезагрузке.
  const connectionGone =
    connectionScope.resolution.kind === 'unavailable' && connectionScope.query.isSuccess

  useEffect(() => {
    if (!connectionGone) return
    // Иначе сайдбар продолжал бы рисовать пункт по имени из хранилища —
    // подключения нет, а строка есть, и пропадает она только при клике.
    setRememberedConnection(undefined)
    setRememberedConnectionName(undefined)
    try {
      window.sessionStorage.removeItem(LAST_CONNECTION_STORAGE_KEY)
      window.sessionStorage.removeItem(LAST_CONNECTION_NAME_STORAGE_KEY)
    } catch {
      // Без хранилища состояние всё равно сброшено в памяти.
    }
  }, [connectionGone])

  const activeConnectionName = connectionGone
    ? undefined
    : (resolvedConnectionName ??
      (locationConnection === undefined ? rememberedConnectionName : undefined))

  useEffect(() => {
    if (activeConnection === undefined || resolvedConnectionName === undefined) return
    setRememberedConnectionName(resolvedConnectionName)
    try {
      window.sessionStorage.setItem(
        LAST_CONNECTION_NAME_STORAGE_KEY,
        resolvedConnectionName,
      )
    } catch {
      // The resolved query value remains available when browser storage is unavailable.
    }
  }, [activeConnection, resolvedConnectionName])

  const activeConnectionPath =
    activeConnection === undefined ? undefined : `/connections/${activeConnection}`
  const connectionRouteActive =
    activeConnectionPath !== undefined && pathname.startsWith(activeConnectionPath)
  const connectionSearchFor = (to: string): { connection?: string } =>
    connectionSearchForRoute(to, activeConnection)
  const items = NAV_ITEMS

  return (
    <aside
      className={cn(
        'flex min-h-0 min-w-0 shrink-0 flex-col bg-panel',
        mobile ? 'h-full w-full border-0' : 'w-[210px] border-r border-line',
      )}
    >
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-line px-4">
        {CUSTOM_LOGO !== undefined ? (
          <>
            <img src={CUSTOM_LOGO_DARK} alt="Grantor" className="block size-6 object-contain [html[data-theme=light]_&]:hidden" />
            <img src={CUSTOM_LOGO_LIGHT} alt="Grantor" className="hidden size-6 object-contain [html[data-theme=light]_&]:block" />
          </>
        ) : (
          <img src="/favicon.svg" alt="Grantor" className="size-6 object-contain" />
        )}
        <span className="min-w-0">
          <span className="block text-sm font-semibold tracking-wide text-text">Grantor</span>
          <span className="block text-[10px] uppercase tracking-[0.12em] text-faint">Control Plane</span>
        </span>
      </div>

      <nav aria-label="Основная навигация" className="min-w-0 flex-1 space-y-0.5 overflow-x-hidden overflow-y-auto px-2 py-2">
        {items.map((item, itemIndex) => {
          const selfActive = isRouteActive(item.to, pathname)
          const Icon = item.icon
          return (
            <div key={item.to}>
              <Link
                ref={itemIndex === 0 ? initialFocusRef : undefined}
                to={item.to}
                search={connectionSearchFor(item.to)}
                onClick={onNavigate}
                aria-current={selfActive ? 'page' : undefined}
                className={cn(
                  'flex h-8 items-center gap-2.5 px-3 text-[13px]',
                  NAV_ITEM_INTERACTION,
                  selectionSurfaceClassName(selfActive, selfActive ? 'font-medium' : 'text-muted'),
                )}
              >
                <Icon className="size-4 shrink-0" aria-hidden="true" />
                <span>{item.label}</span>
              </Link>
              {item.to === '/overview' &&
                activeConnection !== undefined &&
                activeConnectionName !== undefined && (
                  <Link
                    to="/connections/$connectionId"
                    params={{ connectionId: activeConnection }}
                    onClick={onNavigate}
                    aria-current={connectionRouteActive ? 'page' : undefined}
                    className={cn(
                      'ml-4 flex h-8 items-center gap-2.5 border-l border-line px-3 text-[13px]',
                      NAV_ITEM_INTERACTION,
                      selectionSurfaceClassName(
                        connectionRouteActive,
                        connectionRouteActive ? 'font-medium' : 'text-muted',
                      ),
                    )}
                  >
                    <Cable className="size-4 shrink-0" aria-hidden="true" />
                    <span className="min-w-0 truncate">{activeConnectionName}</span>
                  </Link>
                )}
            </div>
          )
        })}
      </nav>
    </aside>
  )
}
