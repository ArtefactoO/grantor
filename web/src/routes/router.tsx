// Code-based роутер (@tanstack/react-router без file-based codegen):
// дерево маршрутов собирается здесь, страницы живут в соседних файлах.
import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  Outlet,
  redirect,
} from '@tanstack/react-router'
import type { ErrorComponentProps } from '@tanstack/react-router'
import { SearchX } from '@project/ui/icons'
import { AppShell } from '../components/layout/AppShell'
import { EmptyState, ErrorState, Spinner } from '@project/ui'
import { errorMessage } from '../lib/errorMessage'
import { validateConnectionSearch } from '../lib/connection-context'
import { validateOperationTimeSearch } from '../lib/operation-time'
import { legacyControlSearch, validateControlSearch } from '../lib/control-search'

// Каждая страница — отдельный route chunk. Router остаётся единственной
// eager-точкой сборки дерева и не затягивает тяжёлые page modules в entry.
const ConnectionDetailPage = lazyRouteComponent(
  () => import('./connection-detail'),
  'ConnectionDetailPage',
)
const ConnectionStatePage = lazyRouteComponent(
  () => import('./connection-state-page'),
  'ConnectionStatePage',
)
const ControlPage = lazyRouteComponent(() => import('./control'), 'ControlPage')
const OverviewPage = lazyRouteComponent(() => import('./overview'), 'OverviewPage')
const PrincipalsPage = lazyRouteComponent(
  () => import('./principals'),
  'PrincipalsPage',
)
const PrincipalDetailPage = lazyRouteComponent(
  () => import('./principal-detail'),
  'PrincipalDetailPage',
)

function RootLayout() {
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}

export function NotFound() {
  return (
    <EmptyState
      icon={SearchX}
      title="Страница не найдена"
      description="Проверьте адрес или вернитесь к списку подключений."
    />
  )
}

export function RoutePending() {
  return (
    <div className="flex min-h-64 items-center justify-center" role="status">
      <Spinner className="size-5" />
      <span className="sr-only">Загрузка страницы…</span>
    </div>
  )
}

export function RouteError({ error, reset }: ErrorComponentProps) {
  return (
    <ErrorState
      title="Не удалось открыть страницу"
      message={errorMessage(error)}
      onRetry={reset}
    />
  )
}

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFound,
})

// Старый корневой URL остаётся совместимым bookmark, но единственным общим
// каталогом подключений является «Обзор».
const rootIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/overview' })
  },
})

const connectionDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/connections/$connectionId',
  // Deep-link из «Контроля»: вкладка и предвыбранный аккаунт/ресурс.
  validateSearch: (search: Record<string, unknown>): {
    tab?: 'accounts' | 'resources' | 'roles' | 'hba'
    account?: string
    resource?: string
  } => ({
    ...(search.tab === 'accounts' || search.tab === 'resources' || search.tab === 'roles' || search.tab === 'hba'
      ? { tab: search.tab }
      : {}),
    ...(typeof search.account === 'string' && search.account !== ''
      ? { account: search.account }
      : {}),
    ...(typeof search.resource === 'string' && search.resource !== ''
      ? { resource: search.resource }
      : {}),
  }),
  component: ConnectionDetailPage,
})

const connectionStateRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/connections/$connectionId/state',
  component: ConnectionStatePage,
})

const operationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/operations',
  validateSearch: (search) => ({
    ...validateConnectionSearch(search),
    ...validateOperationTimeSearch(search),
  }),
  beforeLoad: ({ search }) => {
    throw redirect({ to: '/control', search: legacyControlSearch(search, 'operations') })
  },
})

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/audit',
  validateSearch: validateConnectionSearch,
  beforeLoad: ({ search }) => {
    // Аудит слился с операциями в «Журнал»: старая закладка открывает его с
    // фильтром «События».
    throw redirect({ to: '/control', search: legacyControlSearch(search, 'operations', 'events') })
  },
})

const controlRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/control',
  component: ControlPage,
  validateSearch: validateControlSearch,
})

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/overview',
  component: OverviewPage,
})

// Экраны этапа principals-drift: раздел «Пользователи» (principals с
// деталью) и сводный отчёт «Дрифт».
const principalsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/principals',
  component: PrincipalsPage,
})

const principalDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/principals/$principalId',
  component: PrincipalDetailPage,
})

const driftRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/drift',
  validateSearch: validateConnectionSearch,
  beforeLoad: ({ search }) => {
    throw redirect({ to: '/control', search: legacyControlSearch(search, 'findings') })
  },
})

// Старые bookmarks ведут в admin-вкладку Control. Сам Control скрывает
// вкладку от младших ролей, а API scope-policies дополнительно admin-gated.
const scopePoliciesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scope-policies',
  beforeLoad: () => {
    throw redirect({ to: '/control', search: { tab: 'environments' } })
  },
})

// Экран «Подтверждения» (ADR-0010): admin подтверждает/отклоняет опасные
// операции, ждущие approval. Сам экран admin-gated внутри компонента.
const approvalsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/approvals',
  beforeLoad: ({ search }) => {
    throw redirect({ to: '/control', search: legacyControlSearch(search, 'operations', 'approval') })
  },
})

// Removed global inventory shells keep only a compatibility redirect. The
// connection page remains the single UI authority for accounts, access,
// resources and roles; old scoped bookmarks still reach that connection.
function legacyConnectionRedirect(search: Record<string, unknown>): never {
  const connection = validateConnectionSearch(search).connection
  if (connection !== undefined) {
    throw redirect({
      to: '/connections/$connectionId',
      params: { connectionId: connection },
    })
  }
  throw redirect({ to: '/overview' })
}

const legacyResourcesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/resources',
  beforeLoad: ({ search }) => legacyConnectionRedirect(search),
})

const legacyAccessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/access',
  beforeLoad: ({ search }) => legacyConnectionRedirect(search),
})

const legacyManifestRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/manifest',
  beforeLoad: ({ search }) => {
    const connection = validateConnectionSearch(search).connection
    if (connection !== undefined) {
      throw redirect({
        to: '/connections/$connectionId/state',
        params: { connectionId: connection },
      })
    }
    throw redirect({ to: '/overview' })
  },
})

const routeTree = rootRoute.addChildren([
  rootIndexRoute,
  connectionDetailRoute,
  connectionStateRoute,
  operationsRoute,
  auditRoute,
  controlRoute,
  overviewRoute,
  legacyResourcesRoute,
  principalsRoute,
  principalDetailRoute,
  legacyAccessRoute,
  legacyManifestRoute,
  driftRoute,
  scopePoliciesRoute,
  approvalsRoute,
])

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
  defaultPendingComponent: RoutePending,
  defaultErrorComponent: RouteError,
  // Быстрый переход не должен мигать короткоживущим spinner-state: кроме
  // визуального шума он меняет высоту контента и дёргает scrollbar.
  defaultPendingMs: 180,
  defaultPendingMinMs: 200,
})

// Регистрация типа роутера — типобезопасные Link/useParams по всему коду.
declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
