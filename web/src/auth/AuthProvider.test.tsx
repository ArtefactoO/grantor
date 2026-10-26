import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../lib/api'
import { AuthProvider } from './AuthProvider'
import { LOGGED_OUT_PATH } from './LoggedOut'

const apiMock = vi.hoisted(() => vi.fn())

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return { ...actual, api: apiMock, setCsrf: vi.fn() }
})

/** Подменяет путь страницы: AuthProvider читает его напрямую из location. */
function atPath(path: string) {
  const original = window.location
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...original, pathname: path, href: original.href },
  })
  return () => {
    Object.defineProperty(window, 'location', { configurable: true, value: original })
  }
}

afterEach(() => {
  apiMock.mockReset()
})

describe('AuthProvider', () => {
  it('показывает экран выхода и не спрашивает сессию', async () => {
    const restore = atPath(LOGGED_OUT_PATH)
    try {
      render(
        <AuthProvider>
          <div>приложение</div>
        </AuthProvider>,
      )

      expect(await screen.findByText('Вы вышли из Grantor')).toBeInTheDocument()
      expect(screen.queryByText('приложение')).not.toBeInTheDocument()
      expect(apiMock).not.toHaveBeenCalled()
    } finally {
      restore()
    }
  })

  // 401 означает, что переход на вход уже начат — ошибку показывать нечего.
  it('не показывает ошибку, когда сессии нет', async () => {
    apiMock.mockRejectedValue(new ApiError(401, 'unauthorized'))

    render(
      <AuthProvider>
        <div>приложение</div>
      </AuthProvider>,
    )

    await waitFor(() => {
      expect(apiMock).toHaveBeenCalled()
    })
    expect(screen.queryByText('Не удалось получить сессию')).not.toBeInTheDocument()
    expect(screen.getByText('Проверка сессии…')).toBeInTheDocument()
  })

  // Сетевой сбой — другое дело: перехода нет, молчание оставит вечный лоадер.
  it('показывает ошибку, когда каталог недоступен', async () => {
    apiMock.mockRejectedValue(new ApiError(0, 'сеть недоступна или API не отвечает'))

    render(
      <AuthProvider>
        <div>приложение</div>
      </AuthProvider>,
    )

    expect(await screen.findByText('Не удалось получить сессию')).toBeInTheDocument()
  })
})
