// Загружает GET /auth/me до рендера приложения и раздаёт сессию через
// React context. 401 внутри api() уводит на /auth/login, поэтому сюда
// попадают только валидные сессии либо сетевые сбои.
import { createContext, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { ApiError, api, setCsrf } from '../lib/api'
import { LOGGED_OUT_PATH, LoggedOut } from './LoggedOut'
import { errorMessage } from '../lib/errorMessage'
import type { Me } from '../lib/types'
import { ScreenLoader, ErrorState } from '@project/ui'

export interface AuthSession {
  email: string
  role: string
  csrfToken: string
}

const AuthContext = createContext<AuthSession | null>(null)

/** Сессия текущего пользователя; кидает вне AuthProvider. */
export function useAuth(): AuthSession {
  const session = useContext(AuthContext)
  if (session === null) {
    throw new Error('useAuth должен вызываться внутри AuthProvider')
  }
  return session
}

// Ранги ролей — зеркало internal/auth/roles.go: admin ⊃ operator ⊃ viewer.
const ROLE_RANK: Record<string, number> = {
  viewer: 0,
  operator: 1,
  admin: 2,
}

/** true, если роль не ниже требуемой; неизвестная роль ничего не может. */
export function roleAtLeast(
  role: string,
  required: 'viewer' | 'operator' | 'admin',
): boolean {
  return (ROLE_RANK[role] ?? -1) >= (ROLE_RANK[required] ?? Number.MAX_SAFE_INTEGER)
}

export interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [session, setSession] = useState<AuthSession | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Единственная страница без сессии: /auth/me на ней заведомо вернёт 401.
  const loggedOut = window.location.pathname === LOGGED_OUT_PATH

  useEffect(() => {
    if (loggedOut) {
      return
    }
    let cancelled = false
    setError(null)
    api<Me>('/auth/me')
      .then((me) => {
        if (cancelled) {
          return
        }
        setCsrf(me.csrf_token, me.csrf_header)
        setSession({ email: me.email, role: me.role, csrfToken: me.csrf_token })
      })
      .catch((err: unknown) => {
        if (cancelled) {
          return
        }
        // 401 не показываем: api() уже начал переход на вход, и карточка
        // ошибки успевала мигнуть перед сменой страницы.
        if (err instanceof ApiError && err.status === 401) {
          return
        }
        setError(errorMessage(err))
      })
    return () => {
      cancelled = true
    }
  }, [loggedOut])

  if (loggedOut) {
    return <LoggedOut />
  }
  if (error !== null) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg p-6">
        <ErrorState
          title="Не удалось получить сессию"
          message={error}
          onRetry={() => {
            window.location.reload()
          }}
        />
      </div>
    )
  }
  if (session === null) {
    return <ScreenLoader label="Проверка сессии…" />
  }
  return <AuthContext.Provider value={session}>{children}</AuthContext.Provider>
}
