// Правый drawer использует тот же Radix Dialog foundation: portal, focus trap,
// inert-фон, scroll lock, Escape и возврат фокуса работают единообразно.
import { useRef } from 'react'
import type { ReactNode, RefObject } from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { motion, useReducedMotion } from 'motion/react'
import { X } from './icons'
import { motionTransition, MOTION_VARIANTS } from './motion'
import { IconButton } from './icon-button'
import { focusModalContent } from './modal-focus'

export interface DrawerProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  description?: ReactNode
  initialFocusRef?: RefObject<HTMLElement | null>
  closeOnOverlayClick?: boolean
}

export function Drawer({
  open,
  onClose,
  title,
  children,
  description,
  initialFocusRef,
  closeOnOverlayClick = true,
}: DrawerProps) {
  const restoreFocusRef = useRef<HTMLElement | null>(null)
  const contentRef = useRef<HTMLDivElement | null>(null)
  const reducedMotion = useReducedMotion()

  return (
    <DialogPrimitive.Root
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) {
          onClose()
        }
      }}
    >
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay asChild>
          <motion.div
            data-slot="drawer-overlay"
            className="fixed inset-0 z-50 bg-black/50"
            initial={reducedMotion ? false : 'hidden'}
            animate="visible"
            exit="exit"
            variants={MOTION_VARIANTS.overlay}
            transition={motionTransition('overlay', reducedMotion)}
          />
        </DialogPrimitive.Overlay>
        <DialogPrimitive.Content
          asChild
          {...(description === undefined ? { 'aria-describedby': undefined } : {})}
          onOpenAutoFocus={(event) => {
            restoreFocusRef.current =
              document.activeElement instanceof HTMLElement ? document.activeElement : null
            event.preventDefault()
            focusModalContent(contentRef.current, initialFocusRef)
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault()
            restoreFocusRef.current?.focus()
            restoreFocusRef.current = null
          }}
          onPointerDownOutside={(event) => {
            if (!closeOnOverlayClick) {
              event.preventDefault()
            }
          }}
        >
          <motion.div
            ref={contentRef}
            data-slot="drawer-content"
            tabIndex={-1}
            className="fixed right-0 top-0 z-50 flex h-full w-[440px] max-w-[92vw] flex-col bg-panel shadow-[var(--shadow-floating)] focus:outline-none"
            initial={reducedMotion ? false : 'hidden'}
            animate="visible"
            exit="exit"
            variants={MOTION_VARIANTS.drawer}
            transition={motionTransition('panel', reducedMotion)}
          >
            <div className="flex h-12 shrink-0 items-center justify-between border-b border-line px-4">
              <DialogPrimitive.Title className="text-sm font-semibold text-text">
                {title}
              </DialogPrimitive.Title>
              <DialogPrimitive.Close asChild>
                <IconButton
                  data-modal-close
                  label="Закрыть"
                  icon={<X aria-hidden="true" className="size-4" />}
                />
              </DialogPrimitive.Close>
            </div>
            {description !== undefined && (
              <DialogPrimitive.Description className="sr-only">
                {description}
              </DialogPrimitive.Description>
            )}
            <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
          </motion.div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
