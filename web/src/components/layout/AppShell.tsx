// Каркас приложения: desktop-sidebar, мобильная навигация в drawer и
// локально скроллящийся контент без горизонтального overflow страницы.
import { useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Drawer } from '@project/ui'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export interface AppShellProps {
  children: ReactNode
}

export function AppShell({ children }: AppShellProps) {
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false)
  const firstNavigationLinkRef = useRef<HTMLAnchorElement>(null)

  return (
    <div className="ui-app-shell flex h-[100dvh] max-w-full overflow-hidden bg-bg text-text">
      <div className="hidden shrink-0 lg:flex">
        <Sidebar />
      </div>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Topbar
          mobileNavigationOpen={mobileNavigationOpen}
          onOpenMobileNavigation={() => setMobileNavigationOpen(true)}
        />
        <main className="ui-app-canvas min-h-0 min-w-0 flex-1 overflow-x-hidden overflow-y-auto [scrollbar-gutter:stable] p-3 sm:p-4 lg:p-6">
          {children}
        </main>
      </div>

      <Drawer
        open={mobileNavigationOpen}
        onClose={() => setMobileNavigationOpen(false)}
        title="Навигация"
        description="Основные разделы Grantor"
        initialFocusRef={firstNavigationLinkRef}
      >
        <Sidebar
          mobile
          initialFocusRef={firstNavigationLinkRef}
          onNavigate={() => setMobileNavigationOpen(false)}
        />
      </Drawer>
    </div>
  )
}
