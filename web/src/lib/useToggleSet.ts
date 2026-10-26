// Хук множества выбранных строковых значений с переключением по одному.
// Убирает повтор `setX(prev => new Set + has?delete:add)` по экранам
// (выбор аккаунтов, kind-фильтры, развёрнутые/свёрнутые узлы).
import { useCallback, useState } from 'react'

export interface ToggleSet {
  /** Текущее множество выбранных значений. */
  set: ReadonlySet<string>
  /** Добавляет значение, если его нет, иначе убирает. */
  toggle: (value: string) => void
  /** Полностью очищает множество. */
  clear: () => void
  /** Заменяет множество указанными значениями. */
  replace: (values: Iterable<string>) => void
}

/** Множество выбранных значений: {set, toggle, clear, replace}. */
export function useToggleSet(): ToggleSet {
  const [set, setSet] = useState<ReadonlySet<string>>(new Set())
  const toggle = useCallback((value: string) => {
    setSet((prev) => {
      const next = new Set(prev)
      if (next.has(value)) {
        next.delete(value)
      } else {
        next.add(value)
      }
      return next
    })
  }, [])
  const clear = useCallback(() => {
    setSet(new Set())
  }, [])
  const replace = useCallback((values: Iterable<string>) => {
    setSet(new Set(values))
  }, [])
  return { set, toggle, clear, replace }
}
