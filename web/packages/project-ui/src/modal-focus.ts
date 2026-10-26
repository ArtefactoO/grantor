import type { RefObject } from 'react'

const INITIAL_FOCUS_SELECTOR = [
  '[data-autofocus]',
  'input:not([disabled]):not([type="hidden"])',
  'textarea:not([disabled])',
  'select:not([disabled])',
  'button:not([disabled]):not([data-modal-close])',
  'a[href]',
  '[tabindex]:not([tabindex="-1"]):not([data-modal-close])',
].join(',')

/**
 * Shared initial-focus policy for modal surfaces.
 *
 * A close action remains in the regular Tab order, but never becomes the
 * automatic first target: focusing it eagerly also opens its tooltip and makes
 * every dialog look as if the user had hovered the close control.
 */
export function focusModalContent(
  content: HTMLElement | null,
  initialFocusRef?: RefObject<HTMLElement | null>,
): void {
  const explicit = initialFocusRef?.current
  if (explicit !== undefined && explicit !== null) {
    explicit.focus({ preventScroll: true })
    return
  }

  const target = content?.querySelector<HTMLElement>(INITIAL_FOCUS_SELECTOR)
  if (target !== undefined && target !== null) {
    target.focus({ preventScroll: true })
    return
  }

  content?.focus({ preventScroll: true })
}
