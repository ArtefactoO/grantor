// Модальный диалог на Radix: portal, focus trap, inert-фон, scroll lock,
// Escape и возврат фокуса обеспечивает headless-примитив. Публичный контракт
// прежний; дополнительные props позволяют явно задать описание и первый фокус.
import { useRef } from 'react'
import type { ReactNode, RefObject } from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { motion, useReducedMotion } from 'motion/react'
import { X } from './icons'
import { motionTransition, MOTION_VARIANTS } from './motion'
import { IconButton } from './icon-button'
import { focusModalContent } from './modal-focus'

export interface DialogProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  description?: ReactNode
  initialFocusRef?: RefObject<HTMLElement | null>
  closeOnOverlayClick?: boolean
  size?: 'default' | 'wide'
}

export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  description,
  initialFocusRef,
  closeOnOverlayClick = true,
  size = 'default',
}: DialogProps) {
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
            data-slot="dialog-overlay"
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
            data-slot="dialog-content"
            tabIndex={-1}
            className={`fixed left-1/2 top-1/2 z-50 flex max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] ${size === 'wide' ? 'max-w-4xl' : 'max-w-lg'} flex-col overflow-hidden rounded-lg bg-panel shadow-[var(--shadow-floating)] focus:outline-none`}
            style={{ transform: 'translate(-50%, -50%)' }}
            initial={reducedMotion ? false : 'hidden'}
            animate="visible"
            exit="exit"
            variants={MOTION_VARIANTS.dialog}
            transition={motionTransition('dialog', reducedMotion)}
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
            <div
              data-slot="dialog-body"
              className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-4"
            >
              {children}
            </div>
            {footer !== undefined && (
              <div
                data-slot="dialog-footer"
                className="shrink-0 border-t border-line bg-panel p-4"
              >
                {footer}
              </div>
            )}
          </motion.div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
