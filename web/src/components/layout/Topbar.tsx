// Верхняя панель: мобильный вход в навигацию, тема, сессия и выход.
import { useState } from 'react'
import { KeyRound, LogOut, Menu } from '@project/ui/icons'
import { useAuth } from '../../auth/AuthProvider'
import { IconButton } from '@project/ui'
import { ThemePicker } from './ThemePicker'
import { MyAPIKeys } from '../my-api-keys'

export interface TopbarProps {
  mobileNavigationOpen: boolean
  onOpenMobileNavigation: () => void
}

export function Topbar({
  mobileNavigationOpen,
  onOpenMobileNavigation,
}: TopbarProps) {
  const auth = useAuth()
  const [apiKeysOpen, setAPIKeysOpen] = useState(false)

  const logout = () => {
    // Логаут — переход целиком: API удалит session cookie и вернёт на логин.
    window.location.href = '/auth/logout'
  }

  return (
    <header className="flex h-14 min-w-0 shrink-0 items-center gap-1.5 border-b border-line bg-panel px-2 sm:gap-3 sm:px-4">
      <IconButton
        label="Открыть навигацию"
        icon={<Menu aria-hidden="true" className="size-4" />}
        onClick={onOpenMobileNavigation}
        aria-haspopup="dialog"
        aria-expanded={mobileNavigationOpen}
        className="lg:hidden"
      />

      <div className="min-w-0 flex-1" />

      <ThemePicker />

      <div className="flex min-w-0 items-center gap-1 border-l border-line pl-2 sm:gap-2 sm:pl-3">
        <span className="hidden max-w-56 truncate text-sm text-text sm:block" title={auth.email}>
          {auth.email}
        </span>
        <span className="hidden rounded-full border border-line bg-panel2 px-2 py-0.5 text-[11px] uppercase tracking-wide text-muted md:inline-flex">
          {auth.role}
        </span>
        <IconButton
          label="Мои API-ключи"
          icon={<KeyRound className="size-4" aria-hidden="true" />}
          onClick={() => setAPIKeysOpen(true)}
          aria-haspopup="dialog"
          aria-expanded={apiKeysOpen}
        />
        <IconButton
          label="Выйти из Grantor"
          icon={<LogOut className="size-4" aria-hidden="true" />}
          onClick={logout}
        />
      </div>
      {apiKeysOpen && <MyAPIKeys key={`${auth.email}:${auth.role}`} onClose={() => setAPIKeysOpen(false)} />}
    </header>
  )
}
