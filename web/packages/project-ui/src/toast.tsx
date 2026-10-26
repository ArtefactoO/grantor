// Тосты с необязательным действием отмены.
//
// Обратимое действие выполняется сразу, а не после диалога: подтверждение
// каждого шага стоит дороже, чем редкая отмена. Отмена здесь — не откат
// транзакции, а обратная операция, поэтому она попадает в аудит наравне с
// прямой; для необратимых действий (удаление, purge) остаётся диалог.
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { X } from './icons'
import { motionTransition, MOTION_VARIANTS } from './motion'
import { Button } from './button'
import { IconButton } from './icon-button'

/** Сколько тост живёт, если его не закрыли: успеть прочитать и передумать. */
const TOAST_TTL_MS = 7000

export interface ToastAction {
  label: string
  onAct: () => void
}

export interface ToastOptions {
  message: string
  tone?: 'info' | 'success' | 'danger'
  action?: ToastAction
}

interface ToastItem extends ToastOptions {
  id: number
}

interface ToastContextValue {
  show: (options: ToastOptions) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

/**
 * Вне провайдера возвращает пустышку: уведомление — вспомогательный слой,
 * и его отсутствие не должно ломать действие, ради которого оно
 * показывается. Провайдер монтируется один раз в main.tsx.
 */
export function useToast(): ToastContextValue {
  return useContext(ToastContext) ?? NO_TOASTS
}

const NO_TOASTS: ToastContextValue = { show: () => undefined }

const TONES: Record<NonNullable<ToastOptions['tone']>, string> = {
  info: 'border-line bg-panel',
  success: 'border-ok/40 bg-ok-soft',
  danger: 'border-danger/40 bg-danger-soft',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const reducedMotion = useReducedMotion()
  const [items, setItems] = useState<ToastItem[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id))
  }, [])

  const show = useCallback((options: ToastOptions) => {
    const id = nextId.current++
    setItems((current) => [...current, { ...options, id }])
    setTimeout(() => dismiss(id), TOAST_TTL_MS)
  }, [dismiss])

  const value = useMemo(() => ({ show }), [show])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[90] flex flex-col items-center gap-2 px-4" role="region" aria-label="Уведомления">
        <AnimatePresence initial={false}>
          {items.map((item) => (
            <motion.div
              key={item.id}
              initial={reducedMotion ? false : 'hidden'}
              animate="visible"
              exit="exit"
              variants={MOTION_VARIANTS.notice}
              transition={motionTransition('feedback', reducedMotion)}
              className={`pointer-events-auto flex w-full max-w-md items-center gap-3 rounded-md border px-3 py-2 text-sm shadow-[var(--shadow-floating)] ${TONES[item.tone ?? 'info']}`}
              role="status"
              aria-live="polite"
            >
              <span className="min-w-0 flex-1 break-words text-text">{item.message}</span>
              {item.action !== undefined && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    item.action?.onAct()
                    dismiss(item.id)
                  }}
                >
                  {item.action.label}
                </Button>
              )}
              <IconButton
                compact
                label="Закрыть уведомление"
                onClick={() => dismiss(item.id)}
                icon={<X aria-hidden="true" className="size-3.5" />}
              />
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}
