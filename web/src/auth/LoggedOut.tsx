// Экран после выхода. Живёт вне роутера: маршруты приложения доступны
// только с сессией, а этот экран нужен именно без неё.
import { LogOut } from '@project/ui/icons'
import { Button } from '@project/ui'

/** Путь, на который уводит /auth/logout (зеркало auth.LoggedOutPath). */
export const LOGGED_OUT_PATH = '/logged-out'

/**
 * Подтверждение выхода. Вход заново не начинается сам: сессия у IdP жива,
 * и редирект вернул бы пользователя внутрь без единого вопроса.
 */
export function LoggedOut() {
  return (
    <div className="flex h-screen items-center justify-center bg-bg p-6">
      <div className="flex max-w-md flex-col items-center gap-3 rounded-lg border border-line bg-panel px-8 py-10 text-center">
        <LogOut aria-hidden={true} className="size-8 text-faint" />
        <div className="text-sm font-medium text-text">Вы вышли из Grantor</div>
        <div className="text-sm text-muted">
          Сессия в Grantor закрыта. Вход в корпоративный каталог остаётся
          активным, поэтому повторный вход не спросит пароль. Чтобы завершить
          его полностью, выйдите в Authentik.
        </div>
        <Button
          className="mt-2"
          onClick={() => {
            window.location.href = '/auth/login'
          }}
        >
          Войти снова
        </Button>
      </div>
    </div>
  )
}
