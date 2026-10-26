// Общие блоки правых панелей деталей экрана подключения: контейнер
// SidePanel, key-value списки, attributes и bindings. Используются и
// вкладкой «Ресурсы» (read-only), и вкладкой «Аккаунты» (с отзывом прав).
import { useEffect, useMemo, useRef } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Braces, KeyRound, Trash2, X } from '@project/ui/icons'
import type { Binding, Permission } from '../lib/types'
import { bindingStatusTone, shortId } from '../lib/status'
import { permissionAccessEntry } from '../lib/access-entries'
import { errorMessage } from '../lib/errorMessage'
import { cn, CopyableValue, IconButton, Spinner, DetailDisclosure } from '@project/ui'
import { isActiveAccessBinding } from '../lib/active-access'
import { motionTransition, MOTION_VARIANTS } from '@project/ui/motion'
import {
  bindingStateLabel,
  bindingStatusLabel,
  ownershipLabel,
} from '../lib/ui-copy'
import { StatusChip } from '../components/ui/badge'
import { ElevatedAccessDot } from '../components/ui/access-chips'
import { useWideInspector } from './use-wide-inspector'
import { useInspectorViewportHeight } from './use-inspector-viewport-height'

export interface SidePanelProps {
  title: string
  onClose: () => void
  children: ReactNode
  /** Дополнительные классы контейнера. */
  className?: string
  /** Show the shared copy action beside the title on hover or keyboard focus. */
  copyTitle?: boolean
}

export interface InspectorSplitLayoutProps {
  content: ReactNode
  inspector: ReactNode | null
}

/**
 * Общий responsive-layout списка и инспектора.
 *
 * Desktop geometry updates immediately so opening an inspector never animates
 * the entire directory. Stickiness belongs to the slot; the mobile SidePanel
 * handles its own overlay and leaves the content geometry unchanged.
 */
export function InspectorSplitLayout({
  content,
  inspector,
}: InspectorSplitLayoutProps) {
  const wide = useWideInspector()
  const inspectorInlineSize = wide && inspector !== null ? 384 : 0

  return (
    <div
      className="flex flex-col items-stretch gap-4 lg:flex-row lg:items-start lg:gap-0"
      style={{ '--inspector-inline-size': `${inspectorInlineSize}px` } as CSSProperties}
    >
      {content}
      {wide ? (
        <div
          data-slot="inspector-layout-slot"
          data-state={inspector === null ? 'closed' : 'open'}
          className="sticky top-4 min-w-0 shrink-0 self-start overflow-hidden"
          style={{ width: inspectorInlineSize }}
        >
          <div className="ml-6 w-[360px]">
            <AnimatePresence initial={false}>{inspector}</AnimatePresence>
          </div>
        </div>
      ) : (
        <AnimatePresence initial={false}>{inspector}</AnimatePresence>
      )}
    </div>
  )
}

/** Правая панель деталей внутри вкладки (не оверлей). */
export function SidePanel({
  title,
  onClose,
  children,
  className,
  copyTitle = false,
}: SidePanelProps) {
  const wide = useWideInspector()
  const reduceMotion = useReducedMotion()
  const panelRef = useRef<HTMLDivElement>(null)
  const viewportHeight = useInspectorViewportHeight(panelRef, wide)
  const restoreFocusRef = useRef<HTMLElement | null>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  if (
    restoreFocusRef.current === null &&
    document.activeElement instanceof HTMLElement
  ) {
    restoreFocusRef.current =
      document.activeElement
  }

  useEffect(() => {
    if (!wide) return

    panelRef.current?.focus({ preventScroll: true })
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented) {
        event.preventDefault()
        onCloseRef.current()
      }
    }
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [wide])

  useEffect(() => () => {
    restoreFocusRef.current?.focus()
    restoreFocusRef.current = null
  }, [])

  const panel = (
    <motion.div
      ref={panelRef}
      {...(wide ? { role: 'dialog', 'aria-label': `Детали: ${title}` } : {})}
      aria-modal={wide ? undefined : true}
      tabIndex={-1}
      data-slot="connection-side-panel"
      data-modal={wide ? 'false' : 'true'}
      style={viewportHeight === undefined ? undefined : { maxHeight: viewportHeight }}
      className={cn(
        // The measured desktop limit excludes the page header above this panel;
        // a viewport-only max-height otherwise leaves its bottom below main.
        'fixed inset-0 z-40 flex max-h-[100dvh] min-w-0 flex-col overflow-hidden border border-line bg-panel shadow-[var(--shadow-floating)] outline-none md:inset-auto md:bottom-4 md:right-4 md:top-16 md:w-[min(420px,calc(100vw-2rem))] md:rounded-lg lg:sticky lg:top-4 lg:z-auto lg:max-h-[calc(100dvh-2rem)] lg:w-[360px] lg:shrink-0 lg:shadow-none',
        className,
      )}
      initial={reduceMotion ? false : 'hidden'}
      animate="visible"
      exit="exit"
      variants={MOTION_VARIANTS.sidePanel}
      transition={motionTransition('panel', reduceMotion)}
    >
      {!wide && (
        <DialogPrimitive.Title className="sr-only">
          {`Детали: ${title}`}
        </DialogPrimitive.Title>
      )}
      <div data-slot="connection-side-panel-header" className="flex min-h-11 shrink-0 items-start justify-between gap-1 border-b border-line px-3 py-1.5">
        <div className="min-w-0 flex-1 font-mono text-[13px] font-semibold" title={title}>
          {copyTitle ? (
            <CopyableValue value={title} label={`Копировать имя ${title}`}>
              {title}
            </CopyableValue>
          ) : (
            <span className="[overflow-wrap:anywhere]">{title}</span>
          )}
        </div>
        <IconButton
          data-modal-close
          label="Закрыть панель"
          icon={<X className="size-4" aria-hidden="true" />}
          onClick={onClose}
          className="shrink-0"
        />
      </div>
      <div
        data-slot="connection-side-panel-body"
        role="region"
        aria-label={`Содержимое панели: ${title}`}
        tabIndex={0}
        className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-3 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent"
      >
        {children}
      </div>
    </motion.div>
  )

  if (wide) return panel

  return (
    <DialogPrimitive.Root open onOpenChange={(open) => !open && onCloseRef.current()}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/50" />
        <DialogPrimitive.Content
          asChild
          aria-describedby={undefined}
          onOpenAutoFocus={(event) => {
            event.preventDefault()
            panelRef.current?.focus({ preventScroll: true })
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault()
            restoreFocusRef.current?.focus()
          }}
        >
          {panel}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}

export interface KeyValueListProps {
  entries: Array<[string, string]>
}

export function KeyValueList({ entries }: KeyValueListProps) {
  return (
    <dl className="space-y-1.5">
      {entries.map(([key, value]) => (
        <div key={key} className="flex items-baseline gap-2 text-sm">
          <dt className="w-28 shrink-0 text-xs text-faint">{key}</dt>
          <dd className="min-w-0 break-all font-mono text-[12px] text-text">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export interface AttributesSectionProps {
  attributes: unknown
}

// Разворачивает attributes (jsonb) в key-value список; не-объекты и пустые
// объекты не показываются.
export function AttributesSection({ attributes }: AttributesSectionProps) {
  const entries = useMemo(() => {
    if (
      typeof attributes !== 'object' ||
      attributes === null ||
      Array.isArray(attributes)
    ) {
      return []
    }
    return Object.entries(attributes as Record<string, unknown>).map(
      ([key, value]): [string, string] => [
        key,
        typeof value === 'string' ? value : JSON.stringify(value),
      ],
    )
  }, [attributes])

  if (entries.length === 0) {
    return null
  }
  return (
    <DetailDisclosure
      label="Атрибуты движка"
      icon={<Braces className="size-4" />}
      summary={(
        <span className="flex items-center gap-1.5 text-xs">
          <span className="font-medium text-text">Атрибуты движка</span>
          <span className="tabular-nums text-faint">{entries.length}</span>
        </span>
      )}
    >
      <KeyValueList entries={entries} />
    </DetailDisclosure>
  )
}

export interface BindingsSectionProps {
  query: {
    data: Binding[] | undefined
    isPending: boolean
    isError: boolean
    error: unknown
  }
  permissionsById: Map<string, Permission>
  emptyText: string
  /**
   * Отзыв binding; кнопка показывается только на строках с
   * desired_state=present. undefined — секция read-only.
   */
  onRevoke?: (binding: Binding) => void
  /** id binding, отзыв которого выполняется — на его строке спиннер. */
  revokingId?: string | null
}

export function BindingsSection({
  query,
  permissionsById,
  emptyText,
  onRevoke,
  revokingId,
}: BindingsSectionProps) {
  const bindings = query.data ?? []
  const active = bindings.filter(isActiveAccessBinding)
  const inactive = bindings.filter((binding) => !isActiveAccessBinding(binding))

  const renderBinding = (binding: Binding, current: boolean) => {
    const permission = permissionsById.get(binding.permission_definition_id)
    const entry = permissionAccessEntry(
      permission,
      shortId(binding.permission_definition_id),
    )
    return (
      <div
        key={binding.id}
        className={cn(
          'flex items-center gap-2 rounded-md border border-line bg-panel2/50 px-2.5 py-1.5',
          !current && 'opacity-60',
        )}
      >
        <span
          className="flex min-w-0 flex-1 items-center gap-1.5 font-mono text-[12px]"
          title={permission?.name ?? binding.permission_definition_id}
        >
          {entry.dangerous && <ElevatedAccessDot />}
          <span className="line-clamp-2 break-words">{entry.label}</span>
        </span>
        {!current ? (
          <StatusChip tone="unmg">
            {binding.desired_state === 'absent'
              ? 'Revoked'
              : binding.observed_state === 'absent'
                ? bindingStateLabel('absent')
                : 'Inactive'}
          </StatusChip>
        ) : binding.desired_state === null ? (
          <>
            <StatusChip tone="unmg">{ownershipLabel('unmanaged')}</StatusChip>
            <StatusChip tone="ok">{bindingStateLabel('present')}</StatusChip>
          </>
        ) : (
          <StatusChip tone={bindingStatusTone(binding.status)}>
            {bindingStatusLabel(binding.status)}
          </StatusChip>
        )}
        {current &&
          onRevoke !== undefined &&
          binding.desired_state === 'present' && (
            <IconButton
              compact
              tone="danger"
              label="Снять роль"
              onClick={() => onRevoke(binding)}
              busy={revokingId === binding.id}
              icon={revokingId === binding.id ? (
                <Spinner className="size-3.5" />
              ) : (
                <Trash2 className="size-3.5" aria-hidden="true" />
              )}
            />
          )}
      </div>
    )
  }

  return (
    <DetailDisclosure
      label="Права доступа"
      icon={<KeyRound className="size-4" />}
      summary={(
        <span className="flex items-center gap-1.5 text-xs">
          <span className="font-medium text-text">Права доступа</span>
          {query.isPending ? (
            <Spinner className="size-3" />
          ) : (
            <span className="tabular-nums text-faint">{active.length}</span>
          )}
        </span>
      )}
    >
      {query.isError ? (
        <div className="text-sm text-danger">{errorMessage(query.error)}</div>
      ) : query.isPending ? (
        <div className="flex justify-center py-4">
          <Spinner />
        </div>
      ) : bindings.length === 0 ? (
        <div className="text-sm text-faint">{emptyText}</div>
      ) : (
        <div className="space-y-3">
          {active.length > 0 ? (
            <div className="space-y-1.5">
              <div className="text-[11px] font-medium text-muted">
                Действующие <span className="tabular-nums">{active.length}</span>
              </div>
              {active.map((binding) => renderBinding(binding, true))}
            </div>
          ) : (
            <div className="text-sm text-faint">Действующих прав нет</div>
          )}
          {inactive.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[11px] font-medium text-faint">
                Неактивные и история{' '}
                <span className="tabular-nums">{inactive.length}</span>
              </div>
              {inactive.map((binding) => renderBinding(binding, false))}
            </div>
          )}
        </div>
      )}
    </DetailDisclosure>
  )
}
