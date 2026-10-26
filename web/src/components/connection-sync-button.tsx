import { useEffect, useRef } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Check, CircleAlert, RefreshCw } from '@project/ui/icons'
import { IconButton, cn } from '@project/ui'
import { useConnectionSync } from '../lib/use-connection-sync'
import { motionTransition, MOTION_VARIANTS } from '@project/ui/motion'

export interface ConnectionSyncButtonProps {
  connectionId: string
  connectionName: string
  disabled?: boolean
  className?: string
  onSuccess?: () => void
}

export function ConnectionSyncButton({
  connectionId,
  connectionName,
  disabled = false,
  className,
  onSuccess,
}: ConnectionSyncButtonProps) {
  const reducedMotion = useReducedMotion()
  const sync = useConnectionSync(connectionId)
  const onSuccessRef = useRef(onSuccess)
  const previousStateRef = useRef(sync.state)
  onSuccessRef.current = onSuccess

  useEffect(() => {
    if (sync.state === 'success' && previousStateRef.current !== 'success') {
      onSuccessRef.current?.()
    }
    previousStateRef.current = sync.state
  }, [sync.state])

  const label =
    sync.state === 'syncing'
      ? `Идёт синхронизация ${connectionName}`
      : sync.state === 'success'
        ? `Снимок ${connectionName} обновлён`
        : sync.state === 'error'
          ? `Повторить синхронизацию ${connectionName}`
          : `Синхронизировать ${connectionName}`

  return (
    <IconButton
      label={label}
      tooltipDetails={sync.failure ?? undefined}
      busy={sync.syncing}
      success={sync.state === 'success'}
      disabled={disabled || sync.syncing}
      icon={
        <span className="relative size-4" aria-hidden="true">
          <AnimatePresence initial={false}>
            <motion.span
              key={sync.state}
              className="absolute inset-0"
              initial={reducedMotion ? false : 'hidden'}
              animate="visible"
              exit="exit"
              variants={MOTION_VARIANTS.statusIcon}
              transition={motionTransition('feedback', reducedMotion)}
            >
              {sync.state === 'success' ? (
                <Check className="size-4" />
              ) : sync.state === 'error' ? (
                <CircleAlert className="size-4" />
              ) : (
                <RefreshCw
                  className={cn('size-4', sync.state === 'syncing' && 'ui-sync-glyph')}
                />
              )}
            </motion.span>
          </AnimatePresence>
          {sync.state === 'syncing' && (
            <span
              className="ui-sync-arc pointer-events-none absolute inset-px rounded-full border-2 border-transparent border-t-current opacity-40"
            />
          )}
        </span>
      }
      onClick={(event) => {
        event.preventDefault()
        event.stopPropagation()
        sync.sync()
      }}
      className={cn(
        'ui-sync-button',
        sync.state === 'error' && 'border-danger/40 text-danger',
        className,
      )}
    />
  )
}
