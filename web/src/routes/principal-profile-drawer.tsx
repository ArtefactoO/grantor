import * as DialogPrimitive from '@radix-ui/react-dialog'
import { motion, useReducedMotion } from 'motion/react'
import { X } from '@project/ui/icons'
import { useEffect, useRef, useState } from 'react'
import { IconButton } from '@project/ui'
import { motionTransition, MOTION_VARIANTS } from '@project/ui/motion'
import { PrincipalProfileContent } from './principal-detail'
import { useWideInspector } from './use-wide-inspector'

export interface PrincipalProfileDrawerProps {
  principalId: string | null
  principalName?: string
  onClose: () => void
}

/** Responsive profile: right inspector on desktop, full-screen drawer on mobile. */
export function PrincipalProfileDrawer({
  principalId,
  principalName,
  onClose,
}: PrincipalProfileDrawerProps) {
  const wide = useWideInspector()
  const reducedMotion = useReducedMotion()
  const [nestedViewOpen, setNestedViewOpen] = useState(false)
  const profileRef = useRef<HTMLElement>(null)
  const returnFocusRef = useRef<HTMLElement | null>(null)

  if (
    principalId !== null &&
    returnFocusRef.current === null &&
    document.activeElement instanceof HTMLElement
  ) {
    returnFocusRef.current = document.activeElement
  }

  useEffect(() => {
    setNestedViewOpen(false)
  }, [principalId])

  return (
    <DialogPrimitive.Root
      open={principalId !== null}
      modal={!wide}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogPrimitive.Portal>
        {!wide && (
          <DialogPrimitive.Overlay asChild>
            <motion.div
              data-slot="principal-profile-overlay"
              className="fixed inset-0 z-50 bg-black/50"
              initial={reducedMotion ? false : 'hidden'}
              animate="visible"
              exit="exit"
              variants={MOTION_VARIANTS.overlay}
              transition={motionTransition('overlay', reducedMotion)}
            />
          </DialogPrimitive.Overlay>
        )}
        <DialogPrimitive.Content
          asChild
          aria-describedby={undefined}
          onInteractOutside={(event) => {
            if (wide) event.preventDefault()
          }}
          onEscapeKeyDown={(event) => {
            if (nestedViewOpen) event.preventDefault()
          }}
          onOpenAutoFocus={(event) => {
            event.preventDefault()
            profileRef.current?.focus({ preventScroll: true })
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault()
            const target = returnFocusRef.current
            returnFocusRef.current = null
            target?.focus()
          }}
        >
          <motion.aside
            ref={profileRef}
            data-slot="principal-profile-content"
            aria-modal={wide ? undefined : true}
            data-modal={wide ? 'false' : 'true'}
            tabIndex={-1}
            className="fixed inset-y-0 right-0 z-50 flex w-full flex-col bg-panel shadow-[var(--shadow-floating)] focus:outline-none sm:w-[min(620px,calc(100vw-2rem))] lg:w-[min(720px,52vw)]"
            initial={reducedMotion ? false : 'hidden'}
            animate="visible"
            exit="exit"
            variants={MOTION_VARIANTS.drawer}
            transition={motionTransition('panel', reducedMotion)}
          >
            <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel2/60 px-4">
              <DialogPrimitive.Title className="min-w-0 truncate text-sm font-semibold text-text">
                {principalName ?? 'Профиль пользователя'}
              </DialogPrimitive.Title>
              <DialogPrimitive.Close asChild>
                <IconButton
                  data-modal-close
                  label="Закрыть профиль"
                  icon={<X className="size-4" />}
                />
              </DialogPrimitive.Close>
            </header>
            <div className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-5">
              {principalId !== null && (
                <PrincipalProfileContent
                  principalId={principalId}
                  embedded
                  onNestedViewChange={setNestedViewOpen}
                  onPurged={onClose}
                />
              )}
            </div>
          </motion.aside>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
